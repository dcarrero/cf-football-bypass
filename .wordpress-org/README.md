# WordPress.org Plugin Assets

Drop the following PNG/JPG files in this directory. They are synced to the
WordPress.org SVN `assets/` folder by `.github/workflows/deploy.yml`.

## Required

- `icon-256x256.png` — plugin icon shown in the WP admin and on the public
  page (256×256 px, PNG, square).
- `banner-772x250.png` — banner shown at the top of the public page on
  WordPress.org (772×250 px).

## Recommended (retina)

- `icon-128x128.png` — small retina icon.
- `banner-1544x500.png` — retina banner.

## Optional

- `screenshot-1.png`, `screenshot-2.png`, … — captures referenced from the
  `== Screenshots ==` section of `readme.txt`. Recommended size: 1200×900
  or similar 4:3 ratio.

## Notes

- This directory is excluded from the plugin zip by `.distignore`. It only
  ships to the WP.org `assets/` folder, never to `trunk/`.
- File names must match exactly. The 10up deploy action publishes whatever
  is here; mismatched names will simply be ignored by WP.org.
