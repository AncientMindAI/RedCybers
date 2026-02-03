/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"] ,
  theme: {
    extend: {
      colors: {
        bg: "#0b0f14",
        panel: "#10161d",
        accent: "#3fffb1",
        accent2: "#36a7ff",
        warn: "#ffb347"
      },
      boxShadow: {
        glow: "0 0 24px rgba(63,255,177,0.25)",
        soft: "0 8px 30px rgba(0,0,0,0.35)"
      }
    }
  },
  plugins: []
};
