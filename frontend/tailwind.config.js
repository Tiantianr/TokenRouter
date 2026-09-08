/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{vue,js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    // 对齐 OpenRouter 的圆角层级：紧凑元素、控件、内容表面和桌面弹窗。
    borderRadius: {
      none: '0px',
      sm: '4px',
      DEFAULT: '4px',
      md: '6px',
      lg: '6px',
      xl: '8px',
      '2xl': '8px',
      '3xl': '8px',
      '4xl': '8px',
      full: '9999px',
      compact: '4px',
      control: '6px',
      surface: '8px',
      dialog: '12px'
    },
    extend: {
      colors: {
        // 主色调与 sub-custom 品牌蓝保持一致，保留本工程的中性背景与布局。
        primary: {
          50: '#eff6ff',
          100: '#dbeafe',
          200: '#bfdbfe',
          300: '#93c5fd',
          400: '#60a5fa',
          500: '#3c80e6',
          600: '#2563eb',
          700: '#1d4ed8',
          800: '#1e40af',
          900: '#1e3a8a',
          950: '#172554'
        },
        // 辅助色使用旧工程的深蓝灰，避免控件保留青色底调。
        accent: {
          50: '#f8fafc',
          100: '#f1f5f9',
          200: '#e2e8f0',
          300: '#cbd5e1',
          400: '#94a3b8',
          500: '#64748b',
          600: '#475569',
          700: '#334155',
          800: '#1e293b',
          900: '#0f172a',
          950: '#020617'
        },
        // 覆盖默认 gray/slate:Tailwind 默认值偏蓝(#1f2937/#0f172a 等),深色模式下会残留蓝调
        // 统一映射到中性 zinc 色相,与 dark 色阶同一体系
        gray: {
          50: '#FAFAFA',
          100: '#F4F4F5',
          200: '#E4E4E7',
          300: '#D4D4D8',
          400: '#A1A1AA',
          500: '#71717A',
          600: '#52525B',
          700: '#3F3F46',
          800: '#27272A',
          900: '#18181B',
          950: '#09090B'
        },
        slate: {
          50: '#FAFAFA',
          100: '#F4F4F5',
          200: '#E4E4E7',
          300: '#D4D4D8',
          400: '#A1A1AA',
          500: '#71717A',
          600: '#52525B',
          700: '#3F3F46',
          800: '#27272A',
          900: '#18181B',
          950: '#09090B'
        },
        // 深色模式背景 - 成熟黑色系(zinc 中性色相),品牌蓝仅作强调色
        // 注意:950 比 900 略亮,历史上作为"提升面"(elevated surface)使用,保持该关系
        dark: {
          50: '#FAFAFA',
          100: '#F0F0F1',
          200: '#D9D9DE',
          300: '#A6A6AF',
          400: '#77777F',
          500: '#55555C',
          600: '#333338',
          700: '#29292E',
          800: '#1F1F23',
          900: '#121215',
          950: '#18181B'
        }
      },
      fontFamily: {
        // 英文使用 OpenRouter 的开源字体，中文继续按现有系统字体顺序回退。
        sans: [
          '"Plus Jakarta Sans Variable"',
          'system-ui',
          '-apple-system',
          'BlinkMacSystemFont',
          'Segoe UI',
          'Roboto',
          'Helvetica Neue',
          'Arial',
          'PingFang SC',
          'Hiragino Sans GB',
          'Microsoft YaHei',
          'sans-serif'
        ],
        mono: [
          '"Geist Mono Variable"',
          'ui-monospace',
          'SFMono-Regular',
          'Menlo',
          'Monaco',
          'Consolas',
          'monospace'
        ]
      },
      boxShadow: {
        // 普通控件和结构表面只用边框分层；浮层、弹窗和品牌发光仍保留较强投影。
        DEFAULT: 'none',
        sm: 'none',
        glass: 'none',
        'glass-sm': 'none',
        glow: '0 0 20px rgba(60, 128, 230, 0.28)',
        'glow-lg': '0 0 40px rgba(37, 99, 235, 0.35)',
        card: 'none',
        'card-hover': 'none',
        'inner-glow': 'inset 0 1px 0 rgba(255, 255, 255, 0.1)'
      },
      backgroundImage: {
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
        'gradient-primary': 'linear-gradient(135deg, #3c80e6 0%, #1d4ed8 100%)',
        'gradient-dark': 'linear-gradient(135deg, #1F1F23 0%, #0F0F11 100%)',
        'gradient-glass':
          'linear-gradient(135deg, rgba(255,255,255,0.1) 0%, rgba(255,255,255,0.05) 100%)',
        'mesh-gradient':
          'radial-gradient(at 40% 20%, rgba(60, 128, 230, 0.14) 0px, transparent 50%), radial-gradient(at 80% 0%, rgba(147, 197, 253, 0.12) 0px, transparent 50%), radial-gradient(at 0% 50%, rgba(37, 99, 235, 0.1) 0px, transparent 50%)'
      },
      animation: {
        'fade-in': 'fadeIn 0.3s ease-out',
        'slide-up': 'slideUp 0.3s ease-out',
        'slide-down': 'slideDown 0.3s ease-out',
        'slide-in-right': 'slideInRight 0.3s ease-out',
        'scale-in': 'scaleIn 0.2s ease-out',
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        shimmer: 'shimmer 2s linear infinite',
        glow: 'glow 2s ease-in-out infinite alternate'
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' }
        },
        slideUp: {
          '0%': { opacity: '0', transform: 'translateY(10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' }
        },
        slideDown: {
          '0%': { opacity: '0', transform: 'translateY(-10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' }
        },
        slideInRight: {
          '0%': { opacity: '0', transform: 'translateX(20px)' },
          '100%': { opacity: '1', transform: 'translateX(0)' }
        },
        scaleIn: {
          '0%': { opacity: '0', transform: 'scale(0.95)' },
          '100%': { opacity: '1', transform: 'scale(1)' }
        },
        shimmer: {
          '0%': { backgroundPosition: '-200% 0' },
          '100%': { backgroundPosition: '200% 0' }
        },
        glow: {
          '0%': { boxShadow: '0 0 20px rgba(60, 128, 230, 0.28)' },
          '100%': { boxShadow: '0 0 30px rgba(37, 99, 235, 0.4)' }
        }
      },
      backdropBlur: {
        xs: '2px'
      }
    }
  },
  plugins: []
}
