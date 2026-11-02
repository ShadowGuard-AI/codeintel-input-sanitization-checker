![A den under a rock shelf with no lettering anywhere: silt and a shell row in size order in the foreground, arms sorting shells inside the shadow of the den mouth, glass sponges fixed behind, and light shafts from far above with plankton drifting in them](intro-banner.png)



# codeintel-Input-Sanitization-Checker

![The whole den wide: shelf across the top, shells lining the approach in size order, crab armour to one side, the teapot to the other, glass sponges behind, three arms at work, and the project name cut like a sounding line mark on a flat stone by the den mouth](banner.png)

![One den under a rock shelf, its mouth dark, shells in a row in bone white at the mouth, crab armour stacked beside them, and one stolen teapot with a single gold glint on its spout, over the project name lettered after sounding line markers, the heading plate](logo.png)

![The den in three bands: glass sponges fixed to rock in open water in the far band, arms curling, uncurling, reaching, and sorting shells in the middle band, and a shell spiral at the den mouth nudged by an arm tip and settling a short way off in the near band, while the den, the shelf, and the teapot stay still](scene.svg)

Analyzes code to identify potential vulnerabilities arising from missing or inadequate input sanitization. Detects places where user-provided input is directly used in sensitive operations, such as database queries or system commands, without proper sanitization. - Focused on Tools for static code analysis, vulnerability scanning, and code quality assurance

![Major separator: a full run of tube worm crowns opening and closing across the page](sep-heavy.svg)

## Install
`git clone https://github.com/ShadowStrikeHQ/codeintel-input-sanitization-checker`

> **Den mouth note, clone line names the wrong house.** The clone line above names ShadowStrikeHQ rather than ShadowGuard-AI. It is kept as printed and flagged here, not mended in the display. The repository LICENSE file carries the MIT License, while the closing line of this README reads Copyright (c) ShadowStrikeHQ; both facts stand as printed.


![Major separator: a full run of tube worm crowns opening and closing across the page](sep-heavy.svg)

## Usage
`./codeintel-input-sanitization-checker [params]`

> **Den mouth note, usage line is a placeholder.** The usage line above is a placeholder that the parser does not accept. The invocation the parser in main.py does accept is `python3 main.py TARGET [--tools bandit flake8 pylint] [--output FILE] [--ignore PATH ...] [--offensive]`, where target is a required positional argument that appears in no parameter entry below.


![Major separator: a full run of tube worm crowns opening and closing across the page](sep-heavy.svg)

## Parameters
- `-h`: Show help message and exit
- `--tools`: No description provided
- `--output`: Output file to write results to.
- `--ignore`: List of files or directories to ignore.
- `--offensive`: No description provided

![Minor separator: a short centred run of tube worm crowns opening and closing](sep-light.svg)

> **Den mouth note, the target argument is missing.** The parameter list below omits target, the required file or directory to scan, without which the program cannot run. Its restoration lives on the website only, marked there, so the gap remains visible where it was found. A further caution from the code: every ignore path must exist before any tool starts, and a missing ignore path ends the run with exit 1.


![Major separator: a full run of tube worm crowns opening and closing across the page](sep-heavy.svg)

## License
Copyright (c) ShadowStrikeHQ

> **Den mouth note, clone line names the wrong house.** The copyright line above names ShadowStrikeHQ rather than ShadowGuard-AI. It is kept as printed and flagged here. The repository LICENSE file carries the MIT License.
