// Mongoose schema for the AnalysisJobs collection (PRD §4.1).
// Used only when MongoDB is connected; the in-memory store mirrors this shape.
import mongoose from 'mongoose';

const { Schema } = mongoose;

const AnalysisJobSchema = new Schema(
  {
    job_id: { type: String, required: true, unique: true, index: true },
    file_name: { type: String, default: 'sample.bin' },
    file_type: {
      type: String,
      enum: ['PDF', 'Image', 'JS', 'Archive', 'Unknown'],
      default: 'Unknown',
    },
    status: {
      type: String,
      enum: ['Pending', 'Extracting', 'ML_Analysis', 'Completed', 'Failed'],
      default: 'Pending',
      index: true,
    },
    sandbox_mode: { type: String, enum: ['Immediate', 'Deep'], default: 'Immediate' },

    // Raw metadata from ingestion (size, sha256, libmagic type, YARA hits).
    metadata: { type: Schema.Types.Mixed, default: {} },

    // Output of the ML pipeline.
    extracted_iocs: { type: [String], default: [] },
    ttps: { type: [String], default: [] },
    summary: { type: String, default: null },
    features: { type: Schema.Types.Mixed, default: {} }, // embeddings, stego, etc.
    clustering: { type: Schema.Types.Mixed, default: {} }, // UMAP/FAISS output
    xai_payload: { type: Schema.Types.Mixed, default: null }, // SHAP/LIME output

    error: { type: String, default: null },
  },
  { timestamps: true },
);

export const AnalysisJob = mongoose.model('AnalysisJob', AnalysisJobSchema);

// Feedback for the self-learning loop (PRD §5.4 / POST /api/v1/feedback).
const FeedbackSchema = new Schema(
  {
    job_id: { type: String, required: true, index: true },
    analyst: { type: String, default: 'anonymous' },
    correct_label: { type: String, default: null }, // e.g. malicious | benign
    corrected_actor: { type: String, default: null },
    notes: { type: String, default: '' },
  },
  { timestamps: true },
);

export const Feedback = mongoose.model('Feedback', FeedbackSchema);
