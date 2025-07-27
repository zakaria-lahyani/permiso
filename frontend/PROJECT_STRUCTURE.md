# 📁 Project Structure & Configuration

This document outlines the complete project structure and configuration files for the Permiso Admin Console.

## 🏗️ Project Directory Structure

```
frontend/
├── public/                          # Static assets
│   ├── index.html                   # Main HTML template
│   ├── favicon.ico                  # Application favicon
│   ├── manifest.json                # PWA manifest
│   ├── robots.txt                   # SEO robots file
│   └── icons/                       # Application icons
│       ├── icon-192x192.png
│       ├── icon-512x512.png
│       └── apple-touch-icon.png
│
├── src/                             # Source code
│   ├── components/                  # Reusable UI components
│   │   ├── ui/                      # Base UI components
│   │   │   ├── Button.tsx
│   │   │   ├── Input.tsx
│   │   │   ├── Modal.tsx
│   │   │   ├── Table.tsx
│   │   │   ├── Card.tsx
│   │   │   ├── Badge.tsx
│   │   │   ├── Alert.tsx
│   │   │   ├── Loading.tsx
│   │   │   └── index.ts
│   │   ├── layout/                  # Layout components
│   │   │   ├── Header.tsx
│   │   │   ├── Sidebar.tsx
│   │   │   ├── Navigation.tsx
│   │   │   ├── Breadcrumb.tsx
│   │   │   └── Layout.tsx
│   │   ├── forms/                   # Form components
│   │   │   ├── FormField.tsx
│   │   │   ├── FormSelect.tsx
│   │   │   ├── FormTextarea.tsx
│   │   │   ├── FormCheckbox.tsx
│   │   │   ├── FormRadio.tsx
│   │   │   └── FormValidation.tsx
│   │   └── charts/                  # Chart components
│   │       ├── LineChart.tsx
│   │       ├── BarChart.tsx
│   │       ├── PieChart.tsx
│   │       ├── AreaChart.tsx
│   │       └── MetricCard.tsx
│   │
│   ├── pages/                       # Page components
│   │   ├── Dashboard/               # Dashboard pages
│   │   │   ├── index.tsx
│   │   │   ├── Overview.tsx
│   │   │   ├── Analytics.tsx
│   │   │   └── SystemHealth.tsx
│   │   ├── Clients/                 # Client management
│   │   │   ├── index.tsx
│   │   │   ├── ClientList.tsx
│   │   │   ├── ClientDetails.tsx
│   │   │   ├── ClientForm.tsx
│   │   │   └── ClientScopes.tsx
│   │   ├── Users/                   # User management
│   │   │   ├── index.tsx
│   │   │   ├── UserList.tsx
│   │   │   ├── UserDetails.tsx
│   │   │   ├── UserForm.tsx
│   │   │   └── UserRoles.tsx
│   │   ├── Roles/                   # Role management
│   │   │   ├── index.tsx
│   │   │   ├── RoleList.tsx
│   │   │   ├── RoleDetails.tsx
│   │   │   ├── RoleForm.tsx
│   │   │   └── RolePermissions.tsx
│   │   ├── Audit/                   # Audit logs
│   │   │   ├── index.tsx
│   │   │   ├── AuditList.tsx
│   │   │   ├── AuditDetails.tsx
│   │   │   └── AuditFilters.tsx
│   │   ├── Settings/                # System settings
│   │   │   ├── index.tsx
│   │   │   ├── GeneralSettings.tsx
│   │   │   ├── SecuritySettings.tsx
│   │   │   ├── JWTSettings.tsx
│   │   │   └── IntegrationSettings.tsx
│   │   └── Auth/                    # Authentication pages
│   │       ├── Login.tsx
│   │       ├── Logout.tsx
│   │       ├── ForgotPassword.tsx
│   │       └── ResetPassword.tsx
│   │
│   ├── hooks/                       # Custom React hooks
│   │   ├── useAuth.ts               # Authentication hook
│   │   ├── useApi.ts                # API interaction hook
│   │   ├── useLocalStorage.ts       # Local storage hook
│   │   ├── useDebounce.ts           # Debounce hook
│   │   ├── usePagination.ts         # Pagination hook
│   │   ├── useWebSocket.ts          # WebSocket hook
│   │   └── usePermissions.ts        # Permission checking hook
│   │
│   ├── services/                    # API and external services
│   │   ├── api/                     # API service modules
│   │   │   ├── auth.ts              # Authentication API
│   │   │   ├── users.ts             # User management API
│   │   │   ├── clients.ts           # Client management API
│   │   │   ├── roles.ts             # Role management API
│   │   │   ├── audit.ts             # Audit logs API
│   │   │   ├── analytics.ts         # Analytics API
│   │   │   └── settings.ts          # Settings API
│   │   ├── http.ts                  # HTTP client configuration
│   │   ├── websocket.ts             # WebSocket service
│   │   └── storage.ts               # Local storage service
│   │
│   ├── store/                       # State management
│   │   ├── slices/                  # Zustand store slices
│   │   │   ├── authSlice.ts         # Authentication state
│   │   │   ├── userSlice.ts         # User management state
│   │   │   ├── clientSlice.ts       # Client management state
│   │   │   ├── roleSlice.ts         # Role management state
│   │   │   ├── auditSlice.ts        # Audit logs state
│   │   │   └── settingsSlice.ts     # Settings state
│   │   ├── index.ts                 # Store configuration
│   │   └── middleware.ts            # Store middleware
│   │
│   ├── utils/                       # Utility functions
│   │   ├── auth.ts                  # Authentication utilities
│   │   ├── validation.ts            # Form validation
│   │   ├── formatting.ts            # Data formatting
│   │   ├── constants.ts             # Application constants
│   │   ├── permissions.ts           # Permission utilities
│   │   ├── date.ts                  # Date utilities
│   │   └── api.ts                   # API utilities
│   │
│   ├── types/                       # TypeScript type definitions
│   │   ├── auth.ts                  # Authentication types
│   │   ├── user.ts                  # User types
│   │   ├── client.ts                # Client types
│   │   ├── role.ts                  # Role types
│   │   ├── audit.ts                 # Audit types
│   │   ├── api.ts                   # API response types
│   │   └── common.ts                # Common types
│   │
│   ├── styles/                      # Styling files
│   │   ├── globals.css              # Global styles
│   │   ├── components.css           # Component styles
│   │   └── tailwind.css             # Tailwind imports
│   │
│   ├── App.tsx                      # Main App component
│   ├── index.tsx                    # Application entry point
│   ├── routes.tsx                   # Route configuration
│   └── env.d.ts                     # Environment type definitions
│
├── tests/                           # Test files
│   ├── __mocks__/                   # Mock files
│   │   ├── api.ts
│   │   └── localStorage.ts
│   ├── components/                  # Component tests
│   │   ├── ui/
│   │   ├── layout/
│   │   └── forms/
│   ├── pages/                       # Page tests
│   │   ├── Dashboard/
│   │   ├── Clients/
│   │   ├── Users/
│   │   └── Roles/
│   ├── hooks/                       # Hook tests
│   ├── services/                    # Service tests
│   ├── utils/                       # Utility tests
│   ├── setup.ts                     # Test setup
│   └── test-utils.tsx               # Test utilities
│
├── docs/                            # Documentation
│   ├── DEPLOYMENT.md                # Deployment guide
│   ├── DEVELOPMENT.md               # Development guide
│   ├── TESTING.md                   # Testing guide
│   └── TROUBLESHOOTING.md           # Troubleshooting guide
│
├── docker/                          # Docker configuration
│   ├── Dockerfile                   # Production Dockerfile
│   ├── Dockerfile.dev               # Development Dockerfile
│   ├── nginx.conf                   # Nginx configuration
│   └── docker-compose.yml           # Docker Compose file
│
├── .env.example                     # Environment variables template
├── .env.local                       # Local environment variables
├── .gitignore                       # Git ignore rules
├── .eslintrc.js                     # ESLint configuration
├── .prettierrc                      # Prettier configuration
├── tailwind.config.js               # Tailwind CSS configuration
├── tsconfig.json                    # TypeScript configuration
├── vite.config.ts                   # Vite configuration
├── package.json                     # NPM package configuration
├── package-lock.json                # NPM lock file
└── README.md                        # Project documentation
```

## 📦 Package.json Configuration

```json
{
  "name": "permiso-admin-console",
  "version": "1.0.0",
  "description": "Admin console for Permiso Auth system",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview",
    "test": "vitest",
    "test:ui": "vitest --ui",
    "test:coverage": "vitest --coverage",
    "lint": "eslint . --ext ts,tsx --report-unused-disable-directives --max-warnings 0",
    "lint:fix": "eslint . --ext ts,tsx --fix",
    "format": "prettier --write \"src/**/*.{ts,tsx,js,jsx,json,css,md}\"",
    "format:check": "prettier --check \"src/**/*.{ts,tsx,js,jsx,json,css,md}\"",
    "type-check": "tsc --noEmit",
    "docker:build": "docker build -t permiso-admin-console .",
    "docker:dev": "docker-compose -f docker/docker-compose.yml up --build",
    "docker:prod": "docker-compose -f docker/docker-compose.prod.yml up --build"
  },
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.8.0",
    "react-query": "^3.39.3",
    "zustand": "^4.3.6",
    "@headlessui/react": "^1.7.13",
    "@heroicons/react": "^2.0.16",
    "recharts": "^2.5.0",
    "date-fns": "^2.29.3",
    "react-hook-form": "^7.43.5",
    "@hookform/resolvers": "^2.9.11",
    "zod": "^3.20.6",
    "axios": "^1.3.4",
    "clsx": "^1.2.1",
    "tailwind-merge": "^1.10.0",
    "react-hot-toast": "^2.4.0",
    "react-table": "^7.8.0",
    "react-virtual": "^2.10.4",
    "framer-motion": "^10.0.1",
    "react-helmet-async": "^1.3.0"
  },
  "devDependencies": {
    "@types/react": "^18.0.28",
    "@types/react-dom": "^18.0.11",
    "@types/react-table": "^7.7.14",
    "@typescript-eslint/eslint-plugin": "^5.54.1",
    "@typescript-eslint/parser": "^5.54.1",
    "@vitejs/plugin-react": "^3.1.0",
    "autoprefixer": "^10.4.14",
    "eslint": "^8.35.0",
    "eslint-plugin-react-hooks": "^4.6.0",
    "eslint-plugin-react-refresh": "^0.3.4",
    "postcss": "^8.4.21",
    "prettier": "^2.8.4",
    "tailwindcss": "^3.2.7",
    "typescript": "^4.9.3",
    "vite": "^4.1.0",
    "vitest": "^0.29.2",
    "@testing-library/react": "^14.0.0",
    "@testing-library/jest-dom": "^5.16.5",
    "@testing-library/user-event": "^14.4.3",
    "jsdom": "^21.1.0",
    "@vitest/coverage-c8": "^0.29.2",
    "@vitest/ui": "^0.29.2",
    "msw": "^1.1.0"
  },
  "engines": {
    "node": ">=16.0.0",
    "npm": ">=8.0.0"
  }
}
```

## ⚙️ Configuration Files

### TypeScript Configuration (tsconfig.json)

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true,
    "baseUrl": ".",
    "paths": {
      "@/*": ["src/*"],
      "@/components/*": ["src/components/*"],
      "@/pages/*": ["src/pages/*"],
      "@/hooks/*": ["src/hooks/*"],
      "@/services/*": ["src/services/*"],
      "@/store/*": ["src/store/*"],
      "@/utils/*": ["src/utils/*"],
      "@/types/*": ["src/types/*"],
      "@/styles/*": ["src/styles/*"]
    }
  },
  "include": ["src", "tests"],
  "references": [{ "path": "./tsconfig.node.json" }]
}
```

### Vite Configuration (vite.config.ts)

```typescript
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      '@/components': path.resolve(__dirname, './src/components'),
      '@/pages': path.resolve(__dirname, './src/pages'),
      '@/hooks': path.resolve(__dirname, './src/hooks'),
      '@/services': path.resolve(__dirname, './src/services'),
      '@/store': path.resolve(__dirname, './src/store'),
      '@/utils': path.resolve(__dirname, './src/utils'),
      '@/types': path.resolve(__dirname, './src/types'),
      '@/styles': path.resolve(__dirname, './src/styles'),
    },
  },
  server: {
    port: 3000,
    host: true,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        secure: false,
      },
      '/ws': {
        target: 'ws://localhost:8000',
        ws: true,
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom'],
          router: ['react-router-dom'],
          ui: ['@headlessui/react', '@heroicons/react'],
          charts: ['recharts'],
          utils: ['date-fns', 'clsx', 'tailwind-merge'],
        },
      },
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./tests/setup.ts'],
    coverage: {
      reporter: ['text', 'json', 'html'],
      exclude: [
        'node_modules/',
        'tests/',
        '**/*.d.ts',
        '**/*.config.*',
      ],
    },
  },
})
```

### Tailwind CSS Configuration (tailwind.config.js)

```javascript
/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        primary: {
          50: '#eff6ff',
          100: '#dbeafe',
          200: '#bfdbfe',
          300: '#93c5fd',
          400: '#60a5fa',
          500: '#3b82f6',
          600: '#2563eb',
          700: '#1d4ed8',
          800: '#1e40af',
          900: '#1e3a8a',
        },
        gray: {
          50: '#f9fafb',
          100: '#f3f4f6',
          200: '#e5e7eb',
          300: '#d1d5db',
          400: '#9ca3af',
          500: '#6b7280',
          600: '#4b5563',
          700: '#374151',
          800: '#1f2937',
          900: '#111827',
        },
        success: {
          50: '#ecfdf5',
          100: '#d1fae5',
          200: '#a7f3d0',
          300: '#6ee7b7',
          400: '#34d399',
          500: '#10b981',
          600: '#059669',
          700: '#047857',
          800: '#065f46',
          900: '#064e3b',
        },
        warning: {
          50: '#fffbeb',
          100: '#fef3c7',
          200: '#fde68a',
          300: '#fcd34d',
          400: '#fbbf24',
          500: '#f59e0b',
          600: '#d97706',
          700: '#b45309',
          800: '#92400e',
          900: '#78350f',
        },
        error: {
          50: '#fef2f2',
          100: '#fee2e2',
          200: '#fecaca',
          300: '#fca5a5',
          400: '#f87171',
          500: '#ef4444',
          600: '#dc2626',
          700: '#b91c1c',
          800: '#991b1b',
          900: '#7f1d1d',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      spacing: {
        '18': '4.5rem',
        '88': '22rem',
      },
      animation: {
        'fade-in': 'fadeIn 0.5s ease-in-out',
        'slide-in': 'slideIn 0.3s ease-out',
        'bounce-in': 'bounceIn 0.6s ease-out',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideIn: {
          '0%': { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(0)' },
        },
        bounceIn: {
          '0%': { transform: 'scale(0.3)', opacity: '0' },
          '50%': { transform: 'scale(1.05)' },
          '70%': { transform: 'scale(0.9)' },
          '100%': { transform: 'scale(1)', opacity: '1' },
        },
      },
    },
  },
  plugins: [
    require('@tailwindcss/forms'),
    require('@tailwindcss/typography'),
    require('@tailwindcss/aspect-ratio'),
  ],
}
```

### ESLint Configuration (.eslintrc.js)

```javascript
module.exports = {
  root: true,
  env: { browser: true, es2020: true },
  extends: [
    'eslint:recommended',
    '@typescript-eslint/recommended',
    'plugin:react-hooks/recommended',
  ],
  ignorePatterns: ['dist', '.eslintrc.js'],
  parser: '@typescript-eslint/parser',
  plugins: ['react-refresh'],
  rules: {
    'react-refresh/only-export-components': [
      'warn',
      { allowConstantExport: true },
    ],
    '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    '@typescript-eslint/explicit-function-return-type': 'off',
    '@typescript-eslint/explicit-module-boundary-types': 'off',
    '@typescript-eslint/no-explicit-any': 'warn',
    'react-hooks/exhaustive-deps': 'warn',
    'prefer-const': 'error',
    'no-var': 'error',
  },
}
```

### Prettier Configuration (.prettierrc)

```json
{
  "semi": false,
  "trailingComma": "es5",
  "singleQuote": true,
  "printWidth": 80,
  "tabWidth": 2,
  "useTabs": false,
  "bracketSpacing": true,
  "bracketSameLine": false,
  "arrowParens": "avoid",
  "endOfLine": "lf"
}
```

### Environment Variables (.env.example)

```bash
# Application Configuration
VITE_APP_NAME=Permiso Admin Console
VITE_APP_VERSION=1.0.0
VITE_APP_DESCRIPTION=Admin console for Permiso Auth system

# API Configuration
VITE_API_BASE_URL=http://localhost:8000
VITE_API_TIMEOUT=30000
VITE_API_RETRY_ATTEMPTS=3

# Authentication Configuration
VITE_AUTH_CLIENT_ID=admin-console
VITE_AUTH_REDIRECT_URI=http://localhost:3000/auth/callback
VITE_AUTH_SCOPE=admin:system admin:users admin:clients admin:roles admin:audit

# WebSocket Configuration
VITE_WS_URL=ws://localhost:8000/ws
VITE_WS_RECONNECT_INTERVAL=5000
VITE_WS_MAX_RECONNECT_ATTEMPTS=10

# Feature Flags
VITE_ENABLE_ANALYTICS=true
VITE_ENABLE_REAL_TIME_UPDATES=true
VITE_ENABLE_AUDIT_LOGS=true
VITE_ENABLE_SYSTEM_MONITORING=true

# Development Configuration
VITE_DEV_MODE=true
VITE_DEBUG_MODE=false
VITE_MOCK_API=false

# Monitoring & Analytics
VITE_SENTRY_DSN=
VITE_GOOGLE_ANALYTICS_ID=
VITE_HOTJAR_ID=

# Security Configuration
VITE_CSP_NONCE=
VITE_TRUSTED_DOMAINS=localhost,127.0.0.1
```

## 🐳 Docker Configuration

### Production Dockerfile

```dockerfile
# Build stage
FROM node:18-alpine as build

WORKDIR /app

# Copy package files
COPY package*.json ./
RUN npm ci --only=production

# Copy source code
COPY . .

# Build application
RUN npm run build

# Production stage
FROM nginx:alpine

# Copy built application
COPY --from=build /app/dist /usr/share/nginx/html

# Copy nginx configuration
COPY docker/nginx.conf /etc/nginx/nginx.conf

# Expose port
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost/health || exit 1

CMD ["nginx", "-g", "daemon off;"]
```

### Development Dockerfile

```dockerfile
FROM node:18-alpine

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm install

# Copy source code
COPY . .

# Expose port
EXPOSE 3000

# Start development server
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
```

### Docker Compose Configuration

```yaml
version: '3.8'

services:
  admin-console:
    build:
      context: .
      dockerfile: docker/Dockerfile.dev
    ports:
      - "3000:3000"
    volumes:
      - .:/app
      - /app/node_modules
    environment:
      - VITE_API_BASE_URL=http://permiso-auth:8000
      - VITE_WS_URL=ws://permiso-auth:8000/ws
    depends_on:
      - permiso-auth
    networks:
      - permiso-network

  permiso-auth:
    image: permiso-auth:latest
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://postgres:password@postgres:5432/permiso
      - REDIS_URL=redis://redis:6379
    depends_on:
      - postgres
      - redis
    networks:
      - permiso-network

  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=permiso
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - permiso-network

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data
    networks:
      - permiso-network

volumes:
  postgres_data:
  redis_data:

networks:
  permiso-network:
    driver: bridge
```

This comprehensive project structure provides a solid foundation for building the Permiso Admin Console with modern React development practices, proper TypeScript configuration, and Docker containerization.