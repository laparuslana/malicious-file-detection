# Malicious File Detection

This project is designed to detect malicious files based on certain characteristics such as file size, entropy, extension, and hash analysis. The system uses machine learning to predict whether a file is safe or potentially harmful. The project consists of the following modules:

## Table of Contents

- [Required Libraries](#required-libraries)
- [Project Structure](#project-structure)
- [How to Expand Your Dataset](#how-to-expand-your-dataset)

## Required Libraries

Make sure to install the following dependencies:
- pandas 
- scikit-learn 
- hashlib 
- requests 
- scipy

## Project Structure

- **`modify.py`**: Generates a CSV dataset by scanning files in a specified directory.
- **`model.py`**: Trains a machine learning model using the created dataset.
- **`predict.py`**: Makes predictions on files in any directory based on the trained model.

## How to Expand Your Dataset

To expand the dataset, place more files with other extensions **(MalwareBazaar, create your own etc...)** in the directory and run `modify.py` again. Each time you run, it will append new features to the `.csv` file, which can be used to retrain the model.
