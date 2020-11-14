const mongoose = require('mongoose');

const { Schema } = mongoose;

const issueSchema = new Schema(
  {
    name: {
      type: String,
      required: true,
    },
    excerpt: {
      type: String,
      maxlength: 100,
      required: true,
    },
    status: {
      name: {
        type: String,
        required: true,
      },
      value: {
        type: Number,
        required: true,
      },
    },
    type: {
      name: {
        type: String,
        required: true,
      },
      value: {
        type: Number,
        required: true,
      },
    },
    date: { type: Number },
    author: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    content: {
      type: String,
      default: '',
    },
    assignTo: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    reassigned: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },
    resolvedByAuthor: {
      type: Boolean,
    },
    resolvedByPerformer: {
      type: Boolean,
    },
    comments: [{
      content: {
        type: String,
        default: '',
      },
      creator: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
      },
    },
    ],
  },
);

issueSchema.set('toObject', {
  transform(doc, ret) {
    const object = ret;
    delete object.__v;
    return object;
  },
});


issueSchema.set('toJSON', {
  transform(doc, ret) {
    const object = ret;
    delete object.__v;
    return object;
  },
});

const Issue = mongoose.model('Issue', issueSchema);

module.exports = Issue;
