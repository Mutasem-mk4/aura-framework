/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                aura: {
                    primary: "#c026d3", // Magenta
                    secondary: "#0891b2", // Cyan
                    dark: "#0a0a0c",
                    card: "#121216"
                }
            }
        },
    },
    plugins: [],
}
