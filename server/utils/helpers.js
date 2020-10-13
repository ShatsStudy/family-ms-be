const reducePropsToObject = (
  propsArray,
  source
) =>
  propsArray.reduce((obj, el) => {
    if (source[el]) {
      return {
        ...obj,
        [el]: source[el]
      };
    }
    return {
      ...obj
    };
  }, {});

const readInsertedObject = (
  fieldName,
  fieldValue,
  req
) => {
  let name = req.body[fieldName];
  let value = req.body[fieldValue];
  if (name && value) {
    let result = {};
    value = Array.isArray(value)
      ? value
      : Array(value);
    name = Array.isArray(name)
      ? name
      : Array(name);

    result = name.reduce(
      (obj, el, idx) => {
        if (value[idx]) {
          return [
            ...obj,
            {
              [fieldName]: el,
              [fieldValue]: value[idx]
            }
          ];
        }
        return [...obj];
      },
      []
    );
    return result;
  }

  return null;
};

module.exports = {
  reducePropsToObject,
  readInsertedObject
};
