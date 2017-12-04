#!/bin/bash

echo "" > ./submodule_tracker.txt
echo "  when any of the submodules have been changed, please execute" >> ./submodule_tracker.txt
echo "this shell script to regenerate submodule_tracker.txt to track" >> ./submodule_tracker.txt
echo "their commit ids in the root repo(askcoin)'s commit history," >> ./submodule_tracker.txt
echo "this is useful one day when we want to reset root repo." >> ./submodule_tracker.txt
echo "" >> ./submodule_tracker.txt
git submodule foreach --recursive 'git log | head -n 1' >> ./submodule_tracker.txt
echo "" >> ./submodule_tracker.txt
git submodule foreach --recursive 'git remote -v' >> ./submodule_tracker.txt
echo "" >> ./submodule_tracker.txt
