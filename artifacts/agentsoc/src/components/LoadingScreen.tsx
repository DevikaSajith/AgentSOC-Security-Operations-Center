import React from 'react';
import { RefreshCw, ArrowRight } from 'lucide-react';
import './LoadingScreen.css';

export interface LoadingScreenProps {
  isFadingOut?: boolean;
  statusText?: string;
  error?: string | null;
  onRetry?: () => void;
  onContinueDemo?: () => void;
}

export function LoadingScreen({
  isFadingOut = false,
  statusText = 'INITIALIZING SECURITY OPERATIONS...',
  error = null,
  onRetry,
  onContinueDemo,
}: LoadingScreenProps) {
  return (
    <div
      className={`agentsoc-loading-screen ${isFadingOut ? 'fade-out' : ''}`}
      role="status"
      aria-live="polite"
      aria-label="Loading AgentSOC"
    >
      <div className="agentsoc-loading-grid" />
      <div className="agentsoc-loading-container">
        {/* Subtle ambient blur behind equalizer */}
        <div className="agentsoc-waveform-ambient" />

        {/* 7-bar magenta/purple animated equalizer */}
        <div className="agentsoc-waveform" aria-hidden="true">
          <div className="agentsoc-waveform-bar" />
          <div className="agentsoc-waveform-bar" />
          <div className="agentsoc-waveform-bar" />
          <div className="agentsoc-waveform-bar" />
          <div className="agentsoc-waveform-bar" />
          <div className="agentsoc-waveform-bar" />
          <div className="agentsoc-waveform-bar" />
        </div>

        {/* Brand Title */}
        <div className="agentsoc-brand-title">AGENTSOC</div>

        {/* Status Text */}
        <div className="agentsoc-status-text">
          {error ? 'GATEWAY OFFLINE' : statusText}
        </div>

        {/* Professional Error & Retry State */}
        {error && (
          <div className="agentsoc-error-container">
            <div className="agentsoc-error-header">
              <span className="agentsoc-error-dot" />
              <span>Backend Unreachable</span>
            </div>
            <p className="agentsoc-error-message">{error}</p>
            <div className="agentsoc-error-actions">
              {onRetry && (
                <button
                  type="button"
                  className="agentsoc-btn-retry"
                  onClick={onRetry}
                >
                  <RefreshCw size={12} />
                  <span>Retry</span>
                </button>
              )}
              {onContinueDemo && (
                <button
                  type="button"
                  className="agentsoc-btn-demo"
                  onClick={onContinueDemo}
                >
                  <span>Launch Demo Mode</span>
                  <ArrowRight size={12} />
                </button>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default LoadingScreen;
