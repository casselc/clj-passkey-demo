import html, { defaultMinifyOptions } from './htmlPlugin.js';
import { squintLoader } from "./squintPlugin.js";

const result = await Bun.build({
  entrypoints: ["./public/index.html"],
  outdir: "./dist",
  sourcemap: "external",
  plugins: [
    html({
      includeExtension: ['.cljs'],
      inline: true,
      minifyOptions: {
        ...defaultMinifyOptions,
        removeRedundantAttributes: false,
        sortAttributes: true,
        sortClassName: true
      },
      plugins: [squintLoader]
    })
  ],
  minify: true,
});
