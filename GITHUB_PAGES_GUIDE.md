# GitHub Pages Deployment Guide for AI Nexus

## Complete Guide to Deploying AI Nexus on GitHub Pages

### Step 1: Install dependencies and build

```bash
# Install dependencies
npm install

# Build for production
npm run build
```

### Step 2: Configure GitHub Pages

You have two main approaches:

#### Option A: Using `gh-pages` branch (recommended)

1. Install the `gh-pages` package:
```bash
npm install gh-pages --save-dev
```

2. Add these scripts to your `package.json`:
```json
"scripts": {
  "predeploy": "npm run build",
  "deploy": "gh-pages -d dist"
}
```

3. Create a `.github/workflows/deploy.yml` file for automatic deployment:

```yaml
name: Deploy to GitHub Pages

on:
  push:
    branches: [ main ]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install dependencies
        run: npm install

      - name: Build
        run: npm run build

      - name: Deploy
        run: npm run deploy
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

#### Option B: Using `docs` folder

1. Change your vite config to output to `docs`:
```typescript
// vite.config.ts
export default defineConfig({
  // ... other config
  build: {
    outDir: 'docs'
  }
})
```

2. In GitHub repo settings:
   - Go to Settings > Pages
   - Select "Deploy from a branch"
   - Choose `main` branch and `/docs` folder

### Step 3: Important Configuration for GitHub Pages

Since this app uses client-side routing (React Router), you need to:

1. Add a `404.html` file in your `dist` folder that redirects to `index.html`
2. Or better, modify your vite config:

```typescript
// vite.config.ts
export default defineConfig({
  // ... other config
  build: {
    outDir: 'dist',
    // Add this for GitHub Pages
    rollupOptions: {
      output: {
        assetFileNames: 'assets/[name]-[hash][extname]'
      }
    }
  }
})
```

### Step 4: Environment Variables

For GitHub Pages, you'll need to handle the Gemini API key differently since environment variables won't work the same way. You have a few options:

1. **Hardcode a default key** (not recommended for production)
2. **Use a proxy server** to handle API requests
3. **Prompt users to enter their own API key** in the UI

### Step 5: Deploy!

```bash
npm run deploy
```

### Troubleshooting Tips

1. **Base URL**: If your repo is `username.github.io/repo-name`, set the base in vite config:
```typescript
base: '/repo-name/'
```

2. **API Issues**: GitHub Pages serves files over HTTPS, but your API endpoint might need to be HTTPS too.

3. **Storage Limitations**: GitHub Pages has some storage limits, so make sure your built app isn't too large.

### Additional Notes

- Make sure all API endpoints in your code are relative or use full URLs
- Test locally with `npm run preview` before deploying
- Consider adding a `.nojekyll` file to your dist folder to prevent GitHub Pages from ignoring files that start with underscores

### Modified Vite Config Example

Here's a complete vite.config.ts example for GitHub Pages:

```typescript
import path from 'path';
import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
    const env = loadEnv(mode, '.', '');
    return {
      base: process.env.GITHUB_PAGES ? '/your-repo-name/' : '/',
      server: {
        port: 3000,
        host: '0.0.0.0',
      },
      plugins: [react()],
      define: {
        'process.env.API_KEY': JSON.stringify(env.GEMINI_API_KEY),
        'process.env.GEMINI_API_KEY': JSON.stringify(env.GEMINI_API_KEY)
      },
      resolve: {
        alias: {
          '@': path.resolve(__dirname, '.'),
        }
      },
      build: {
        outDir: 'dist',
        rollupOptions: {
          output: {
            assetFileNames: 'assets/[name]-[hash][extname]',
            entryFileNames: 'assets/[name]-[hash].js',
            chunkFileNames: 'assets/[name]-[hash].js'
          }
        }
      }
    };
});
```

### Package.json Updates

Make sure your package.json has these scripts:

```json
"scripts": {
  "dev": "vite",
  "build": "vite build",
  "preview": "vite preview",
  "predeploy": "npm run build",
  "deploy": "gh-pages -d dist"
}
```

### Final Deployment Checklist

1. ✅ Install all dependencies (`npm install`)
2. ✅ Build the project (`npm run build`)
3. ✅ Configure GitHub Pages settings in your repo
4. ✅ Set up GitHub Actions workflow (optional but recommended)
5. ✅ Test locally with `npm run preview`
6. ✅ Deploy with `npm run deploy`
7. ✅ Wait a few minutes and visit your GitHub Pages URL

Your AI Nexus app should now be live on GitHub Pages! 🎉
