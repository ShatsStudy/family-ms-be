const url = require('url');
const Issues = require('../../../models/issue.model');
const config = require('../../../config/config');
const helper = require('../../../utils/helpers');

const arrKeys = config.arrKeysIssues;

const getOneByQuery = async (req, res) => {
  try {
    const { query } = url.parse(req.url, true);
    const {
      status, type, date, userId,
    } = query;
    const issues = await Issues.find({
      $or: [{ 'status.name': status },
        { 'type.name': type },
        { date },
        { author: userId },
        { assignTo: userId }],
    })
      .populate('assignTo', ['firstName', 'lastName'])
      .populate('author', ['firstName', 'lastName'])
      .populate('comments.creator', ['firstName', 'lastName'])
      .exec();
    if (!status && !type && !date && !userId) {
      res.status(404).json({
        err: 'Issue not found',
      });
    }
    res.json(issues);
  } catch (err) {
    res.status(500).json({
      err,
    });
  }
};

const createOne = async (req, res) => {
  try {
    const parameters = helper.reducePropsToObject(arrKeys, req.body);
    const newIssue = Issues({
      ...parameters,
      status: {
        name: req.body.statusName,
        value: req.body.statusValue,
      },
      type: {
        name: req.body.typeName,
        value: req.body.typeValue,
      },
      date: new Date().getTime(),
    });
    await newIssue.save();
    res.status(201).json({
      id: newIssue._id,
    });
  } catch (err) {
    res.status(500).json({
      err,
    });
  }
};

const updateOne = async (req, res) => {
  try {
    const {
      id,
      statusName,
      statusValue,
      typeName,
      typeValue,
      assignTo,
      reassigned,
    } = req.body;
    const parameters = arrKeys.reduce((obj, el) => {
      if (req.body[el]) {
        if (el === 'statusName' || el === 'statusValue') {
          if ((!statusName && statusValue) || (statusName && !statusValue)) {
            res.json({
              err: 'You should enter statusName and statusValue options',
            });
          }
          if (statusName && statusValue) {
            return {
              ...obj,
              status: {
                name: statusName,
                value: statusValue,
              },
            };
          }
        }
        if ((!typeName && typeValue) || (typeName && !typeValue)) {
          res.json({
            err: 'You should enter typeName and typeValue options',
          });
        }
        if (el === 'typeName' || el === 'typeValue') {
          if (typeName && typeValue) {
            return {
              ...obj,
              type: {
                name: typeName,
                value: typeValue,
              },
            };
          }
        }
        return {
          ...obj,
          [el]: req.body[el],
        };
      }
      return {
        ...obj,
      };
    }, {});
    const issue = await Issues.findByIdAndUpdate(id, parameters, { new: true })
      .exec();
    if (!issue) {
      res.status(404).json({
        err: 'Issue not found',
      });
    } else if (!assignTo || !reassigned) {
      res.json({
        err: 'You should enter assignTo and reassigned options',
      });
    }
    res.status(200).json({
      updated: 'Successfully',
    });
  } catch (err) {
    res.status(500).json({
      err,
    });
  }
};

const deleteOne = async (req, res) => {
  try {
    const { id } = req.params;
    const issue = await Issues.findByIdAndDelete(id)
      .exec();
    if (!issue) {
      res.status(404).json({
        err: 'Issue not found',
      });
    }
    res.status(204).json({
      deleted: 'Successfully',
    });
  } catch (err) {
    res.status(500).json({
      err,
    });
  }
};

const getAll = async (req, res) => {
  try {
    const issues = await Issues.find()
      .populate('assignTo', ['firstName', 'lastName'])
      .populate('author', ['firstName', 'lastName'])
      .populate('reassigned', ['firstName', 'lastName'])
      .exec();
    res.status(200).json(issues);
  } catch (err) {
    res.status(500).json({
      err,
    });
  }
};

const updateForResolve = async (req, res) => {
  try {
    const { id } = req.body;
    const { userId } = req.body;
    const issues = await Issues.findById(id);
    if (!issues) {
      res.status(404).json({
        err: 'Issue not found',
      });
    } else if (!req.body.userId) {
      res.json({
        err: 'You should enter userId',
      });
    }
    let resolve;
    if (userId === issues.author.toString() && userId === issues.assignTo.toString()) {
      resolve = {
        resolvedByAuthor: true,
        resolvedByPerformer: true,
      };
    } else if (userId === issues.author.toString()) {
      resolve = { resolvedByAuthor: true };
    } else if (userId === issues.assignTo.toString()) {
      resolve = { resolvedByPerformer: true };
    } else {
      res.json({
        err: 'No author or performer with this id was found',
      });
    }
    await Issues.findByIdAndUpdate(id, resolve, { new: true })
      .exec();
    res.status(200).json({
      updated: 'Successfully',
    });
  } catch (err) {
    res.status(500).json({
      err,
    });
  }
};

const updateForComment = async (req, res) => {
  try {
    const { id } = req.body;
    const issue = await Issues.findById(id);
    if (!issue) {
      res.status(404).json({
        err: 'Issue not found',
      });
    }
    const comments = helper.readInsertedObject('content', 'creator', req);
    issue.comments = [...issue.comments, ...comments];
    issue.save();
    res.status(200).json({
      updated: 'Successfully',
    });
  } catch (err) {
    res.status(500).json({
      err,
    });
  }
};

module.exports = {
  getOneByQuery,
  createOne,
  updateOne,
  deleteOne,
  getAll,
  updateForResolve,
  updateForComment,
};
