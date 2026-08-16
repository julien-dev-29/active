def readFile():
    dictFile = open("words.txt", "r")
    for word in dictFile.readlines():
        word = word.strip('\n')