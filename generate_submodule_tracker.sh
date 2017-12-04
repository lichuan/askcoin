#!/bin/bash

#   when any of the submodules have been changed, please execute
# this shell script to regenerate submodule_tracker.txt to track
# their commit ids in the root repo(askcoin)'s commit history,
# this is useful one day when we want to reset root repo.

echo "" > ./submodule_tracker.txt
git submodule foreach --recursive 'git log | head -n 1' >> ./submodule_tracker.txt
echo "" >> ./submodule_tracker.txt
git submodule foreach --recursive 'git remote -v' >> ./submodule_tracker.txt
echo "" >> ./submodule_tracker.txt
