import React, { useMemo } from 'react';
import ForceGraph2D from 'react-force-graph-2d';

const NeuralMap = ({ data }) => {
  const graphData = useMemo(() => {
    if (!data) {
      // Dummy data for initialization
      return {
        nodes: [
          { id: 'arc.net', group: 1, val: 20 },
          { id: 'api.arc.net', group: 2, val: 10 },
          { id: 'static.arc.net', group: 2, val: 10 },
          { id: 'vuln-sqli', group: 3, val: 15, color: '#ff0000' },
          { id: 'vuln-xss', group: 3, val: 8, color: '#ff0000' },
        ],
        links: [
          { source: 'arc.net', target: 'api.arc.net' },
          { source: 'arc.net', target: 'static.arc.net' },
          { source: 'api.arc.net', target: 'vuln-sqli' },
          { source: 'static.arc.net', target: 'vuln-xss' },
        ]
      };
    }
    return data;
  }, [data]);

  return (
    <div className="w-full h-full bg-black/10">
      <ForceGraph2D
        graphData={graphData}
        nodeLabel="id"
        nodeAutoColorBy="group"
        linkColor={() => 'rgba(255, 255, 255, 0.1)'}
        nodeCanvasObject={(node, ctx, globalScale) => {
          const label = node.id;
          const fontSize = 12 / globalScale;
          ctx.font = `${fontSize}px Inter`;
          const textWidth = ctx.measureText(label).width;
          const bckgDimensions = [textWidth, fontSize].map(n => n + fontSize * 0.2);

          ctx.fillStyle = 'rgba(13, 13, 31, 0.8)';
          ctx.fillRect(node.x - bckgDimensions[0] / 2, node.y - bckgDimensions[1] / 2, ...bckgDimensions);

          ctx.textAlign = 'center';
          ctx.textBaseline = 'middle';
          ctx.fillStyle = node.color || '#00FFFF';
          ctx.fillText(label, node.x, node.y);

          // Glow effect for critical nodes
          if (node.group === 3) {
            ctx.shadowBlur = 15;
            ctx.shadowColor = '#ff0000';
          } else {
            ctx.shadowBlur = 0;
          }
        }}
        cooldownTicks={100}
      />
    </div>
  );
};

export default NeuralMap;
