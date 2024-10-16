// multiply can take any number of arguments and return their product
const multiply = (...arguments) => {
  let result = 1;

  for (let arg of arguments) result *= arg;

  return result;
};

module.exports = multiply;
