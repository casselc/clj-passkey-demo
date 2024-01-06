import html, { defaultHtmlOptions } from './htmlPlugin.js';
import { squintLoader } from "./squintPlugin.js";

const result = await Bun.build({
  entrypoints: ["./public/index.html"],
  outdir: "./dist",
  sourcemap: "external",
  plugins: [
    html({
      build: ['.cljs'],
      inline: true,
      minify: false,
      htmlOptions: { ...defaultHtmlOptions, removeRedundantAttributes: false },
      plugins: [squintLoader]
    })
  ],
  minify: true,
});
