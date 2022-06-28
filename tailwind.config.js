/** @type {import('tailwindcss').Config} */
module.exports = {
  mode: "jit",
  content: ["./src/main/resources/templates/**/*.{html,js}"],
  theme: {
    extend: {},
  },
  daisyui: {
    themes: [
      {
        mytheme: {
          "primary": "#edb89a",
          "secondary": "#4974ff",
          "accent": "#ffadce",
          "neutral": "#1C2630",
          "base-100": "#FFFFFF",
          "info": "#95CEEF",
          "success": "#2BB174",
          "warning": "#ECA855",
          "error": "#F64328",
        },
      },
    ],
  },
  plugins: [require("daisyui")],
}
