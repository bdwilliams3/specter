import { useCallback } from 'react'
import ReactFlow, {
  Background,
  BackgroundVariant,
  Controls,
  MiniMap,
  type Node,
  type Edge,
  type NodeMouseHandler,
} from 'reactflow'
import 'reactflow/dist/style.css'
import AssetNode, { type AssetNodeData } from './AssetNode'

const nodeTypes = { assetNode: AssetNode }

interface TopologyGraphProps {
  nodes: Node<AssetNodeData>[]
  edges: Edge[]
  onNodeClick: (node: Node<AssetNodeData>) => void
}

function getEdgeStyle(edge: Edge): Partial<Edge> {
  const isUntrusted = edge.data?.trust === 'untrusted' || edge.data?.trusted === false
  const edgeType = edge.data?.edge_type ?? ''
  const isAnimated = edgeType === 'data_flow' || edgeType === 'api_call'

  return {
    ...edge,
    animated: isAnimated,
    style: {
      stroke: isUntrusted ? '#ef4444' : '#6366f1',
      strokeWidth: 1.5,
      strokeDasharray: isUntrusted ? '5 3' : undefined,
    },
    labelStyle: { fill: '#94a3b8', fontSize: 10 },
    labelBgStyle: { fill: '#1a1d27' },
  }
}

export default function TopologyGraph({ nodes, edges, onNodeClick }: TopologyGraphProps) {
  const styledEdges = edges.map(getEdgeStyle) as Edge[]

  const handleNodeClick: NodeMouseHandler = useCallback(
    (_event, node) => {
      onNodeClick(node as Node<AssetNodeData>)
    },
    [onNodeClick]
  )

  return (
    <ReactFlow
      nodes={nodes}
      edges={styledEdges}
      nodeTypes={nodeTypes}
      onNodeClick={handleNodeClick}
      fitView
      fitViewOptions={{ padding: 0.2 }}
      minZoom={0.1}
      maxZoom={2}
      proOptions={{ hideAttribution: true }}
    >
      <Background
        variant={BackgroundVariant.Dots}
        gap={20}
        size={1}
        color="#2a2d3e"
      />
      <Controls
        className="!bg-specter-surface !border-specter-border"
        style={{ left: 12, top: 12, bottom: 'auto' }}
      />
      <MiniMap
        nodeColor={(node) => {
          const score = (node.data as AssetNodeData)?.risk_score
          if (score === undefined) return '#6366f1'
          if (score < 30) return '#22c55e'
          if (score < 60) return '#eab308'
          return '#ef4444'
        }}
        maskColor="rgba(15,17,23,0.7)"
        style={{ background: '#1a1d27', border: '1px solid #2a2d3e' }}
      />
    </ReactFlow>
  )
}
