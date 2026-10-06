import { Component, type ErrorInfo, type ReactNode } from 'react'
import { ArrowLeft, Bug, RefreshCw } from 'lucide-react'
import { Button } from './Ui'

type ErrorBoundaryProps = { children: ReactNode; scope?: 'app' | 'page'; resetKey?: string }
type ErrorBoundaryState = { hasError: boolean; message: string }

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { hasError: false, message: '' }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, message: error.message || 'An unexpected error occurred.' }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error(`NetDefender ${this.props.scope || 'app'} boundary:`, error, info.componentStack)
  }

  componentDidUpdate(previousProps: ErrorBoundaryProps) {
    if (this.state.hasError && previousProps.resetKey !== this.props.resetKey) this.setState({ hasError: false, message: '' })
  }

  retry = () => this.setState({ hasError: false, message: '' })

  render() {
    if (!this.state.hasError) return this.props.children
    const page = this.props.scope === 'page'
    return <section className={page ? 'page-error-boundary' : 'error-boundary'} role="alert">
      <div className="error-boundary-icon"><Bug size={22} /></div>
      <span className="eyebrow">SAFE MODE · {page ? 'PAGE RECOVERY' : 'WORKSPACE RECOVERY'}</span>
      <h1>{page ? 'This page hit an unexpected error.' : 'Something interrupted the console.'}</h1>
      <p>{page ? 'The rest of your workspace is still available. Retry this page or choose another section.' : 'The application caught an unexpected error so your workspace is protected.'}</p>
      <code>{this.state.message}</code>
      <Button onClick={this.retry}><RefreshCw size={15} /> Try again</Button>
      {!page && <button className="error-back" onClick={() => window.location.reload()}><ArrowLeft size={14} /> Reload console</button>}
    </section>
  }
}
