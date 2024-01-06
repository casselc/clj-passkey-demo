import html from './htmlPlugin.js';
import { squintLoader } from "./squintPlugin.js";

const result = await Bun.build({
  entrypoints: ["./public/index.html"],
  outdir: "./dist",
  sourcemap: "external",
  plugins: [
    html({
      build: ['.cljs'],
      inline: true,
      plugins: [squintLoader],
    })
  ],
  minify: true,
});

console.log("Build complete", result);