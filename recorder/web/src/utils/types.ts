export type SessionStatus = "recording" | "completed" | "interrupted" | "failed";

export interface Session {
  id: string;
  peer_id: string;
  peer_name: string;
  peer_ip: string;
  source_peer_id: string;
  source_peer_name: string;
  source_peer_ip: string;
  user_id_hash: string;
  os_username: string;
  started_at: string;
  ended_at?: string;
  exit_code?: number;
  cols: number;
  rows: number;
  status: SessionStatus;
}

export interface SessionListResponse {
  sessions: Session[];
  total: number;
  limit: number;
  offset: number;
}
