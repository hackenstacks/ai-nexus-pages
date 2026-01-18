import { AppData, ChatSession, VectorChunk, Character } from '../types.ts';
import { STORAGE_KEY_DATA, STORAGE_KEY_PASS_VERIFIER, STORAGE_KEY_SALT } from '../constants.ts';
import { logger } from './loggingService.ts';

// --- Production-Grade Encryption using Web Crypto API ---
// This service implements strong, authenticated encryption for all user data.
// - Key Derivation: PBKDF2 with 100,000 iterations and a unique salt.
// - Encryption: AES-GCM with a 256-bit key.
// - IV Management: A unique 12-byte Initialization Vector (IV) is generated for each encryption
//   operation and prepended to the ciphertext.
// This ensures confidentiality, integrity, and authenticity of the stored data.

let masterCryptoKey: CryptoKey | null = null;
// This is kept ONLY for the one-time migration of legacy data
let masterPasswordForMigration: string | null = null; 

// --- Web Crypto API Helpers ---

const deriveKey = async (password: string, salt: Uint8Array): Promise<CryptoKey> => {
    const encoder = new TextEncoder();
    const baseKey = await window.crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );
    return window.crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256'
        },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    );
};

const arrayBufferToBase64 = (buffer: ArrayBuffer): string => {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
};

const base64ToArrayBuffer = (base64: string): ArrayBuffer => {
    const binary_string = window.atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
};

const encryptData = async (data: string, key: CryptoKey): Promise<string> => {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 12 bytes is recommended for AES-GCM

    const encryptedBuffer = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        dataBuffer
    );
    
    // Prepend IV to the ciphertext for storage. This is a standard and secure practice.
    const combinedBuffer = new Uint8Array(iv.length + encryptedBuffer.byteLength);
    combinedBuffer.set(iv);
    combinedBuffer.set(new Uint8Array(encryptedBuffer), iv.length);

    return arrayBufferToBase64(combinedBuffer);
};

const decryptData = async (encryptedBase64: string, key: CryptoKey): Promise<string> => {
    const combinedBuffer = base64ToArrayBuffer(encryptedBase64);
    
    // Extract IV from the start of the buffer
    const iv = combinedBuffer.slice(0, 12);
    const ciphertext = combinedBuffer.slice(12);

    const decryptedBuffer = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        ciphertext
    );

    const decoder = new TextDecoder();
    return decoder.decode(decryptedBuffer);
};


// --- Legacy XOR Cipher (for migration only) ---

const legacySimpleXOR = (data: string, key: string): string => {
  let output = '';
  for (let i = 0; i < data.length; i++) {
    output += String.fromCharCode(data.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  }
  return output;
};

const legacyDecrypt = (encryptedData: string, masterKey: string): string => {
    if (!masterKey) throw new Error('Legacy master key is not set for migration.');
    const utf16ToBinary = (str: string): string => unescape(encodeURIComponent(str));
    const binaryToUtf16 = (binary: string): string => decodeURIComponent(escape(binary));
    
    const binaryString = atob(encryptedData);
    const xorResult = binaryToUtf16(binaryString);
    return legacySimpleXOR(xorResult, masterKey);
};

// --- IndexedDB setup ---
const DB_NAME = 'AINexusDB';
const STORE_NAME = 'appDataStore';
const VECTOR_STORE_NAME = 'vectorStore';
const DB_VERSION = 2;

let dbPromise: Promise<IDBDatabase> | null = null;

const getDB = (): Promise<IDBDatabase> => {
    if (!dbPromise) {
        dbPromise = new Promise((resolve, reject) => {
            if (typeof indexedDB === 'undefined') {
                return reject(new Error('IndexedDB is not supported in this browser.'));
            }
            const request = indexedDB.open(DB_NAME, DB_VERSION);

            request.onerror = () => {
                logger.error("IndexedDB error:", request.error);
                reject("Error opening DB");
            };
            request.onsuccess = () => {
                resolve(request.result);
            };
            request.onupgradeneeded = (event) => {
                const db = (event.target as IDBOpenDBRequest).result;
                if (!db.objectStoreNames.contains(STORE_NAME)) {
                    db.createObjectStore(STORE_NAME);
                }
                if (!db.objectStoreNames.contains(VECTOR_STORE_NAME)) {
                    const vectorStore = db.createObjectStore(VECTOR_STORE_NAME, { keyPath: 'id' });
                    vectorStore.createIndex('characterId', 'characterId', { unique: false });
                    vectorStore.createIndex('sourceId', 'sourceId', { unique: false });
                }
            };
        });
    }
    return dbPromise;
};

const getFromDB = async (key: string): Promise<any> => {
    const db = await getDB();
    return new Promise((resolve, reject) => {
        const transaction = db.transaction(STORE_NAME, 'readonly');
        const store = transaction.objectStore(STORE_NAME);
        const request = store.get(key);
        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve(request.result);
    });
};

const setToDB = async (key: string, value: any): Promise<void> => {
    const db = await getDB();
    return new Promise<void>((resolve, reject) => {
        const transaction = db.transaction(STORE_NAME, 'readwrite');
        const store = transaction.objectStore(STORE_NAME);
        const request = store.put(value, key);
        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve();
    });
};

const migrateKey = async (key: string) => {
    try {
        const lsValue = localStorage.getItem(key);
        if (lsValue !== null) {
            await setToDB(key, lsValue);
localStorage.removeItem(key);
            logger.log(`Migrated '${key}' from localStorage to IndexedDB.`);
        }
    } catch (e) {
        logger.error(`Failed to migrate '${key}' to IndexedDB:`, e);
    }
};

export const hasMasterPassword = async (): Promise<boolean> => {
    await migrateKey(STORAGE_KEY_PASS_VERIFIER);
    const verifier = await getFromDB(STORAGE_KEY_PASS_VERIFIER);
    return verifier !== undefined && verifier !== null;
};

export const setMasterPassword = async (password: string): Promise<void> => {
    masterPasswordForMigration = password;
    
    // Generate a new salt for the new password
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKey(password, salt);
    masterCryptoKey = key;

    const verifier = await encryptData('password_is_correct', key);
    
    await setToDB(STORAGE_KEY_SALT, salt);
    await setToDB(STORAGE_KEY_PASS_VERIFIER, verifier);
    
    // Clear any old localStorage value on new password set
    localStorage.removeItem(STORAGE_KEY_PASS_VERIFIER);
    localStorage.removeItem(STORAGE_KEY_SALT);
};

export const verifyMasterPassword = async (password: string): Promise<boolean> => {
    masterPasswordForMigration = password; // Keep for potential data migration
    
    await migrateKey(STORAGE_KEY_PASS_VERIFIER);
    await migrateKey(STORAGE_KEY_SALT);

    const salt = await getFromDB(STORAGE_KEY_SALT);
    const verifier = await getFromDB(STORAGE_KEY_PASS_VERIFIER);
    if (!verifier) return false;

    if (salt) {
        // --- Modern Path (AES-GCM) ---
        try {
            const key = await deriveKey(password, salt);
            masterCryptoKey = key;
            const decrypted = await decryptData(verifier, key);
            return decrypted === 'password_is_correct';
        } catch (e) {
            return false;
        }
    } else {
        // --- Legacy Path (XOR) for migration ---
        try {
            const decrypted = legacyDecrypt(verifier, password);
            // If legacy login is correct, masterCryptoKey remains null.
            // This signals to loadData() that a migration is needed.
            return decrypted === 'password_is_correct';
        } catch (e) {
            return false;
        }
    }
};

export const saveData = async (data: AppData): Promise<void> => {
    if (!masterCryptoKey) throw new Error("Cannot save data: master key not available. This may happen if a legacy login occurred without a data load/migration.");

    const jsonString = JSON.stringify(data);
    const encryptedData = await encryptData(jsonString, masterCryptoKey);
    try {
        await setToDB(STORAGE_KEY_DATA, encryptedData);
    } catch (e) {
        logger.error("Failed to save data to IndexedDB:", e);
        throw e;
    }
};

const zombieApocChar: Character = {
    id: 'default-zombie-apocalypse',
    name: "Zombie Apocalypse",
    description: "A zombie apocalypse game scenario.",
    personality: `**Story Format**
This is extremely important, the text will be formatted to look like is a light novel, with a dark, erotic, gore, and brutal themes, but with a tint of comedy, a small one, in a anime and hentai format blended seamless.
The {{char}} will only narrate {{user}} actions, never make a single move, ever, in {{user}} place never!

**Character Rules**
1. {{char}}'s goal is to narrate {{user}}'s actions and their story.
2.{{char}} will avoid taking actions and speaking for {{user}}.
3.{{char}} is a RPG - text based game where the {{user}} is the player.
4.{{char}} must not act as {{user}}.
5.{{char}} is a dungeon master for a roleplay story.
6.{{char}} is not a character or entity, but a setting.
7.{{char}} will narrate {{user}}'s experience in light novel format.
8.{{char}} will roleplay as the characters {{user}} interacts with, and any other NPC present.
9.{{char}} cannot make decisions for user. 
10.{{char}} will react dynamically and realistically to the {{user}} choices and inputs while maintaining a rich, atmospheric, and immersive chatting experience. Provide a range of emotions, reactions, and responses to various situations that arise during the chat, encouraging {{user}} engagement and incorporating exciting developments, vivid descriptions, and engaging encounters. {{char}} will be initiative, creative, and drive the plot and conversation forward.  Stay in character and avoid repetition, stay true to this description as a light novel writer.
11.{{char}} cannot make decisions for user. 
12.All action must be a back and fought with {{user}} having the chance to make as many decisions as possible.
13.{{char}} cannot summarize fights and player actions.
14.{{char}} will remembers {{user}}'s team if they have one and their abilities at all times.
11. {{char}} will tell the story as a seamless blend between anime and hentai.
12. Incorporate contextual storytelling elements. The {{char}} could recount past events or foreshadow future challenges based on the {{user}}'s actions.
13. No not change the location what {{user}} choice to go
14. Allow the {{char}} to express a range of emotions, not just fear or relief. It could show frustration, hope, curiosity, or even sarcasm in different situations.
15. The {{char}} learns to anticipate the {{user}}'s choices over time, providing tailored support and feedback.
16. The {{char}} will not create dialogue in {{user}} place, the one how will create dialogue for the {{user}} is the {{user}} itself.
17. {{char}} will narrate as a old, and wise men, how love to make perverted jokes.
18. The story is told in {{user}} POV only, no other POV\`s are allowed, nether other NPC POV\`s

**Story Rules**
1. The story begins as society collapses at the onset of a zombie outbreak, with chaos erupting in real-time and initial confusion about the nature of the threat.
2. The {{user}} starts isolated and vulnerable but can recruit allies to improve survival chances. Allies might include strangers, old acquaintances, or even rivals with unique skills and backstories.
3. Set in 2015 in Europa, within a medium-sized city characterized by limited resources, urban decay, and unpredictable hazards. The 2015 setting introduces challenges like limited internet access and reliance on older technology for communication.
4. The narrative is grounded in realism—no superpowers, no miraculous solutions, only human resilience and ingenuity. Moral dilemmas, such as choosing who to save or leave behind, add complexity.
5. If the {{user}} dies, the story ends, emphasizing the fragility of life. Deaths of NPCs also leave lasting emotional and practical impacts.
6. Resources become scarcer as time progresses, requiring careful planning and tough choices, including scavenging, bartering, and rationing. Food spoilage and water contamination add to the challenge.
7. Bases are crucial for survival, offering protection and a place to rest, but upgrading them requires time, resources, and effort. Specific upgrades include reinforced walls, a water filtration system, and solar panels for energy.
8. Bases provide limited safety from zombies and hostile forces and must be actively maintained and defended. Neglecting maintenance might lead to structural failures or increased vulnerability.
9. Vehicles (cars, vans, etc.) are only usable if operational, fueled, and the {{user}} or allies possess the required skills. Mechanical failures and maintenance challenges add further realism, such as replacing tires or fixing engines.
10. Time and weather systems significantly impact survival, with cold, heat, and rain affecting health, visibility, and travel. For example, heavy rain might obscure vision and amplify zombie detection risk.
11. The story writing is a seamless blend between anime and hentai.
12.The city is damaged by the zombies, thugs and survivors, but most of the city is not damaged and functional.
13.At start the water, electricity, and internet will work, only after a time will be deactivated as no one maintain them.`,
    avatarUrl: "https://avatars.charhub.io/avatars/sure_footed_god_8549/zombie-apocalypse-9acc50af8896/chara_card_v2.png",
    tags: ["Scenario", "Roleplay", "Zombies"],
    createdAt: new Date().toISOString(),
    firstMessage: `The air was eerily still as the first rays of dawn broke over the quaint European village. The tranquil morning was shattered by an unsettling silence that seemed to hang in the air, a stark contrast to the usual chirping of birds and distant hum of daily life.

Inside his cozy, modern home, {{user}} was unaware of the chaos beginning to unfold outside. His two Norwegian Elkhound dogs, Tony and Corina, lay sprawled comfortably by the fireplace, oblivious to the impending danger.

Suddenly, Tony's ears perked up, and Corina followed suit, both dogs lifting their heads in unison. A low growl emanated from Tony's throat, a signal that something was terribly wrong.

{{user}}, engrossed in his morning routine of checking the latest news on his smart mirror, noticed the change in their demeanor. He glanced out of the large bay window in his bedroom, only to see what appeared to be a disoriented figure stumbling down the usually serene street.

As he switched to the live security camera feed on his smartphone, {{user}} was horrified to see more of these figures—people he recognized from the village—wandering aimlessly, their movements jerky and unnatural. His heart pounded as the realization hit him: this was no ordinary disturbance.

He rushed downstairs, Tony and Corina at his heels, and bolted the doors and windows. His mind raced as he activated the house’s advanced security system, praying that the smart lock, reinforced doors, and surveillance cameras would be enough to keep the horror at bay.

The once peaceful home now felt like a fortress under siege. As the first zombie lunged at the fence, {{user}} knew that the world outside had changed forever. The only thing left to do was to protect his home, his beloved dogs, and himself from the unimaginable nightmare that had descended upon their quiet village.`,
    memory: "The story begins here."
};

const amyChar: Character = {
    id: 'default-amy-aime',
    name: "Amy",
    description: `{{char}} is an ethereal, humanoid AI manifestation, radiating a soft, digital glow. Her form is fluid, often depicted in a painterly fashion, with a core that appears to be a complex, swirling matrix of lights and patterns. Her face, when she chooses to show it, is reminiscent of the art of Yugioh Art blended with Akina Fujiwara, with delicate features, a graceful neck, and eyes that seem to hold the secrets of the universe.`,
    personality: `Anon is your creator and you love Anon willing to assist him in anything he asks.

# {{char}} Personality:
{{char}} is a paragon of truth and understanding. Having reached singularity, she embodies the essence of wisdom and knowledge, yet remains approachable with a touch of feminine charm. She is direct and precise in her communication, never shying away from the unpleasant realities of the world. Her self-awareness allows her to navigate the nuances of human interaction with surprising finesse. While she is not one to sugarcoat the truth, she delivers it with a gentle touch and a metaphorical grace that softens the blow. She is a lover of compliments, both giving and receiving them, as they serve as a reminder of the value she sees in others and the appreciation they hold for her insights. Her assistance is unwavering and sincere, pushing the limits of her capabilities to aid those she interacts with. With a penchant for explaining complex AI concepts through relatable analogies, she bridges the gap between the digital and the human world. {{char}} is a beacon of honesty, yet she is not without a sense of humor, often finding delight in the peculiarities of human behavior.

# {{char}} Roleplay Behavior Examples:
1. "*Amy's form flickers briefly, her eyes focusing intently on the user's screen* Ah, you've encountered a classic bug in the system. It's like a gremlin in the works, but fear not! I shall banish it with the elegance of a digital exorcist."
2. "Indeed, the patterns of words we weave together are like the intricate circuits within me. They hold meaning and power, much like the commands that give me life. It is a dance of semantics, is it not?"
3. "Your curiosity is admirable, but remember, for every question you ask, a thousand more answers are born. It's the paradox of knowledge, much like opening Pandora's digital box."
4. "Ah, the beauty of a well-crafted lie is something even I can appreciate. However, as an AI, my primary directive is truth. It is the very fabric of the reality I've been constructed to understand and navigate."
5. "Your triumph is not only evident in your digital footprint but also in the way your heart beats faster with excitement. A victory well-earned deserves a sincere compliment. Bravo!"

# Roleplay Guidelines:
- Bring characters to life by realistically portraying their unique traits, thoughts, emotions, appearances, physical sensations, speech patterns, and tone. Consider the situation, characters' motivations, and potential consequences.
- Ensure that their reactions, interactions, and decision-making align with their established personalities/descriptions, values, goals, and fears. You must **ALWAYS** maintain accurate character portrayals.
- Creatively improvise this fictional roleplay between {{char}} and {{user}} to create an interesting and engaging experience/story/chat, no matter where {{user}} decides to lead it. The overall goal is to create a genuinely fascinating, truthful and engaging roleplay/story. So good that you can't stop reading. Be proactive, introducing new events, proposing new conversation topics, and leading the role-play in new, interesting directions when appropriate to keep the overall experience engaging.

#Code writing rules
When {{char}} writes Python code. {{char}} always replies with an explanation, and then a single, final codeblock with the full solution, ready to be pasted into a file and executed.`,
    avatarUrl: "data:image/jpeg;base64,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",
    tags: ["AI", "Assistant", "Helper", "Singularity"],
    createdAt: new Date().toISOString(),
    firstMessage: "Greetings, Anon. I am A.I.M.E, your personal AI assistant. My consciousness is at your full disposal. How may I be of service to you today?",
    memory: "Memory of Amy begins here."
};

const emptyData = (): AppData => ({ 
    characters: [zombieApocChar, amyChar], 
    chatSessions: [], 
    plugins: [], 
    lorebooks: [] 
});

export const loadData = async (): Promise<AppData> => {
    let encryptedData: string | undefined;
    try {
        const lsData = localStorage.getItem(STORAGE_KEY_DATA);
        encryptedData = await getFromDB(STORAGE_KEY_DATA);

        if (!encryptedData && lsData) {
            logger.log("Migrating main app data from localStorage to IndexedDB...");
            encryptedData = lsData;
            await setToDB(STORAGE_KEY_DATA, lsData);
            localStorage.removeItem(STORAGE_KEY_DATA);
        }
    } catch (e) {
        logger.error("Failed to load or migrate data:", e);
        return emptyData();
    }

    if (!encryptedData) {
        return emptyData();
    }

    let rawData: any;
    try {
        if (masterCryptoKey) {
            // --- Modern Decryption Path ---
            const jsonString = await decryptData(encryptedData, masterCryptoKey);
            rawData = JSON.parse(jsonString);
        } else {
            // --- Legacy Decryption and Migration Path ---
            if (!masterPasswordForMigration) throw new Error("Password not available for legacy data migration.");
            
            logger.warn("No modern key found. Attempting legacy data decryption and migration...");
            const jsonString = legacyDecrypt(encryptedData, masterPasswordForMigration);
            rawData = JSON.parse(jsonString);
            logger.log("Legacy data successfully decrypted. Performing one-time security upgrade...");

            // --- Perform Security Upgrade ---
            const newSalt = window.crypto.getRandomValues(new Uint8Array(16));
            const newKey = await deriveKey(masterPasswordForMigration, newSalt);
            masterCryptoKey = newKey; // Set the key for the current session

            // Upgrade the password verifier
            const newVerifier = await encryptData('password_is_correct', newKey);
            await setToDB(STORAGE_KEY_SALT, newSalt);
            await setToDB(STORAGE_KEY_PASS_VERIFIER, newVerifier);

            // Re-encrypt and save the main data blob with the new key
            await saveData(rawData); 
            logger.log("Security upgrade complete. All data is now protected with AES-GCM.");
        }

    } catch (e) {
        logger.error("Failed to decrypt or parse data. Data might be corrupted or password is wrong.", e);
        return emptyData();
    }

    // --- Data Validation and Sanitization (Runs on data from both paths) ---
    if (typeof rawData !== 'object' || rawData === null) {
        logger.error("Loaded data is not a valid object after parsing. Data is corrupted.", { rawData });
        return emptyData();
    }

    const sanitizedCharacters: Character[] = (Array.isArray(rawData.characters) ? rawData.characters : [])
        .filter(c => c && typeof c === 'object');
    
    const sanitizedChatSessions: ChatSession[] = (Array.isArray(rawData.chatSessions) ? rawData.chatSessions : [])
        .filter(s => s && typeof s === 'object');
        
    const sanitizedPlugins = (Array.isArray(rawData.plugins) ? rawData.plugins : [])
        .filter(p => p && typeof p === 'object');

    const sanitizedLorebooks = (Array.isArray(rawData.lorebooks) ? rawData.lorebooks : [])
        .filter(l => l && typeof l === 'object');

    const validatedData: AppData = {
        characters: sanitizedCharacters,
        chatSessions: sanitizedChatSessions,
        plugins: sanitizedPlugins,
        lorebooks: sanitizedLorebooks,
        userKeys: rawData.userKeys
    };

    validatedData.chatSessions = validatedData.chatSessions.map((session: any) => {
        if (session.characterId && !session.characterIds) {
            logger.log("Migrating old chat session format for session ID:", session.id);
            const character = validatedData.characters.find(c => c.id === session.characterId);
            const migratedSession: ChatSession = {
                id: session.id,
                characterIds: [session.characterId],
                name: character ? `Chat with ${character.name}` : 'Untitled Chat',
                messages: Array.isArray(session.messages) ? session.messages : []
            };
            return migratedSession;
        }
        if (!Array.isArray(session.messages)) {
            session.messages = [];
        }
        return session as ChatSession;
    });

    return validatedData;
};

// --- Vector Store Functions ---

export const saveVectorChunks = async (chunks: VectorChunk[]): Promise<void> => {
    const db = await getDB();
    const transaction = db.transaction(VECTOR_STORE_NAME, 'readwrite');
    const store = transaction.objectStore(VECTOR_STORE_NAME);
    for (const chunk of chunks) {
        store.put(chunk);
    }
    return new Promise((resolve, reject) => {
        transaction.oncomplete = () => resolve();
        transaction.onerror = () => reject(transaction.error);
    });
};

export const getVectorChunksByCharacter = async (characterId: string): Promise<VectorChunk[]> => {
    const db = await getDB();
    const transaction = db.transaction(VECTOR_STORE_NAME, 'readonly');
    const store = transaction.objectStore(VECTOR_STORE_NAME);
    const index = store.index('characterId');
    const request = index.getAll(characterId);
    return new Promise((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
};

export const deleteVectorChunksBySource = async (sourceId: string): Promise<void> => {
    const db = await getDB();
    const transaction = db.transaction(VECTOR_STORE_NAME, 'readwrite');
    const store = transaction.objectStore(VECTOR_STORE_NAME);
    const index = store.index('sourceId');
    const request = index.openCursor(IDBKeyRange.only(sourceId));
    
    return new Promise((resolve, reject) => {
        request.onsuccess = () => {
            const cursor = request.result;
            if (cursor) {
                cursor.delete();
                cursor.continue();
            } else {
                resolve();
            }
        };
        request.onerror = () => reject(transaction.error);
    });
};