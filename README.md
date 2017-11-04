# Lynx

Dodgy reflective DLL injector PoC for 32-bit Windows.

![GUI](https://i.imgur.com/7zM8Uzj.jpg)

![Demo](https://i.imgur.com/ZWj85Zk.jpg)

## How to Compile

Use MSVC++ because MinGW doesn't support `wWinMain`, though you can port it over if you wish.

## TODO List

1. Implement GUI
2. Add module to update the payload dynamically (without need to recompile)
3. Implement obfuscation option for the payload