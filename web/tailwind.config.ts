import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: ["class"],
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./lib/**/*.{ts,tsx}"
  ],
  theme: {
    extend: {
      colors: {
        ink: "#070B14",
        steel: "#111A2B",
        pulse: "#06D6A0",
        skyline: "#30B2F8",
        amberline: "#F2C14E"
      },
      boxShadow: {
        glass: "0 12px 40px rgba(0, 0, 0, 0.35)",
        neon: "0 0 0 1px rgba(48, 178, 248, 0.35), 0 0 35px rgba(48, 178, 248, 0.14)"
      },
      backgroundImage: {
        "mesh-radial": "radial-gradient(circle at 20% 20%, rgba(48,178,248,0.22), transparent 40%), radial-gradient(circle at 80% 0%, rgba(6,214,160,0.2), transparent 50%), radial-gradient(circle at 50% 80%, rgba(242,193,78,0.16), transparent 35%)"
      }
    }
  },
  plugins: []
};

export default config;
