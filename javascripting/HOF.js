function repeat(operation, num) {
    if (num > 0) { operation(); return repeat(operation, num - 1) } // SOLUTION GOES HERE
}

// Do not remove the line below
module.exports = repeat
