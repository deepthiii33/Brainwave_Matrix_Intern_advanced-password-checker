# 🔐 Advanced Password Strength Checker

Welcome to the **Advanced Password Strength Checker**, a project built as part of the **Brainwave Matrix Internship**. This project helps users evaluate the strength of their passwords using **entropy calculations, dictionary checks, and pattern recognition**.

It includes **two versions**:
- ✅ **Command-Line Interface (CLI)**
- ✅ **Graphical User Interface (GUI)** (using Tkinter)

---

## 🚀 Features

### ✅ Common Features (Both CLI & GUI)
- Checks passwords against known breached passwords (`rockyou.txt`)
- Calculates password **entropy** for strength estimation
- Estimates time to crack under different attack scenarios
- Detects **keyboard patterns** and **common words/names**
- Provides actionable suggestions to improve password strength

###  Command-Line Version
- Color-coded output
- Emoji-based strength indicator
- Fast and scriptable

###  GUI Version
- Simple Tkinter-based interface
- Password input & analysis at a click
- Result display with warnings and suggestions
- Supports checking multiple passwords from a file (multiple_pass.txt)

---

## 📷 Screenshots

###  CLI Version
| Weak Password Example | Strong Password Example |
|-----------------------|-------------------------|
| ![](https://github.com/deepthiii33/Brainwave_Matrix_Intern_advanced-password-checker/blob/main/CLI/CLI%20Weak%20Password.png) | ![](https://github.com/deepthiii33/Brainwave_Matrix_Intern_advanced-password-checker/blob/main/CLI/CLI%20Strong%20Password.png) |

###  GUI Version
| Single Password Check | Multiple Password Check |
|---------------|-----------------------|
| ![](https://github.com/deepthiii33/Brainwave_Matrix_Intern_advanced-password-checker/blob/main/GUI/Gui%20single%20password.png) | ![](https://github.com/deepthiii33/Brainwave_Matrix_Intern_advanced-password-checker/blob/main/GUI/Gui%20multiple%20password.png) |

---

## ⚙️ Requirements

- Python 3.x
- Dependencies:
  - colorama
  - tkinter (usually pre-installed with Python)
  - wordninja or nltk for further enhancements (Optional) 
- Install dependencies if required:
   `` pip install colorama``


##  Usage
 - ✅ CLI Version : ``python3 password_checker.py``
 - ✅ GUI Version : ``python3 password_checker_gui.py``

## Checking Multiple Passwords in GUI
Add your passwords (one per line) to the multiple_pass.txt file in the GUI folder.Click Check Multiple Passwords to process them all.

## Conclusion
This project demonstrates practical techniques for assessing password strength using both command-line and graphical interfaces. It highlights the importance of using strong, unpredictable passwords to protect against modern attack methods.
