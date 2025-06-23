echo "# backup-test-project" >> README.md
git init
git add README.md
git commit -m "first commit"
git branch -M main
git remote add origin https://github.com/RamzaPH/backup-test-project.git
git push -u origin main
