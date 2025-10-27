/**
 * NetworkMap Component
 * Interactive network topology visualization using D3.js
 */

import React, { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';

interface Node {
  id: string;
  name: string;
  type: 'target' | 'compromised' | 'pivot' | 'attacker';
  ip?: string;
  os?: string;
  vulnerabilities?: number;
  x?: number;
  y?: number;
  fx?: number | null;
  fy?: number | null;
}

interface Link {
  source: string | Node;
  target: string | Node;
  type: 'attack' | 'pivot' | 'c2';
  strength?: number;
}

interface NetworkMapProps {
  nodes: Node[];
  links: Link[];
  width?: number;
  height?: number;
  onNodeClick?: (node: Node) => void;
  onNodeDoubleClick?: (node: Node) => void;
}

const NetworkMap: React.FC<NetworkMapProps> = ({
  nodes,
  links,
  width = 1200,
  height = 800,
  onNodeClick,
  onNodeDoubleClick
}) => {
  const svgRef = useRef<SVGSVGElement>(null);
  const [selectedNode, setSelectedNode] = useState<Node | null>(null);
  const [zoom, setZoom] = useState<d3.ZoomBehavior<SVGSVGElement, unknown> | null>(null);

  useEffect(() => {
    if (!svgRef.current || nodes.length === 0) return;

    // Clear previous content
    d3.select(svgRef.current).selectAll('*').remove();

    // Create SVG
    const svg = d3.select(svgRef.current)
      .attr('width', width)
      .attr('height', height)
      .attr('viewBox', `0 0 ${width} ${height}`);

    // Create container group for zoom
    const g = svg.append('g');

    // Setup zoom behavior
    const zoomBehavior = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.1, 4])
      .on('zoom', (event) => {
        g.attr('transform', event.transform);
      });

    svg.call(zoomBehavior);
    setZoom(zoomBehavior);

    // Create force simulation
    const simulation = d3.forceSimulation<Node>(nodes)
      .force('link', d3.forceLink<Node, Link>(links)
        .id((d) => d.id)
        .distance(150)
        .strength(0.5)
      )
      .force('charge', d3.forceManyBody().strength(-500))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(50));

    // Create arrow markers for directed edges
    svg.append('defs').selectAll('marker')
      .data(['attack', 'pivot', 'c2'])
      .enter().append('marker')
      .attr('id', (d) => `arrow-${d}`)
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 25)
      .attr('refY', 0)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', (d) => {
        switch (d) {
          case 'attack': return '#ef4444';
          case 'pivot': return '#f59e0b';
          case 'c2': return '#8b5cf6';
          default: return '#6b7280';
        }
      });

    // Create links
    const link = g.append('g')
      .attr('class', 'links')
      .selectAll('line')
      .data(links)
      .enter().append('line')
      .attr('stroke', (d) => {
        switch (d.type) {
          case 'attack': return '#ef4444';
          case 'pivot': return '#f59e0b';
          case 'c2': return '#8b5cf6';
          default: return '#6b7280';
        }
      })
      .attr('stroke-width', 2)
      .attr('stroke-opacity', 0.6)
      .attr('marker-end', (d) => `url(#arrow-${d.type})`);

    // Create node groups
    const node = g.append('g')
      .attr('class', 'nodes')
      .selectAll('g')
      .data(nodes)
      .enter().append('g')
      .attr('class', 'node')
      .call(d3.drag<SVGGElement, Node>()
        .on('start', dragStarted)
        .on('drag', dragged)
        .on('end', dragEnded)
      );

    // Add circles to nodes
    node.append('circle')
      .attr('r', 20)
      .attr('fill', (d) => {
        switch (d.type) {
          case 'attacker': return '#8b5cf6';
          case 'compromised': return '#ef4444';
          case 'pivot': return '#f59e0b';
          case 'target': return '#3b82f6';
          default: return '#6b7280';
        }
      })
      .attr('stroke', '#fff')
      .attr('stroke-width', 2)
      .on('click', (event, d) => {
        event.stopPropagation();
        setSelectedNode(d);
        if (onNodeClick) onNodeClick(d);
      })
      .on('dblclick', (event, d) => {
        event.stopPropagation();
        if (onNodeDoubleClick) onNodeDoubleClick(d);
      });

    // Add icons to nodes
    node.append('text')
      .attr('text-anchor', 'middle')
      .attr('dy', '.35em')
      .attr('fill', '#fff')
      .attr('font-size', '16px')
      .text((d) => {
        switch (d.type) {
          case 'attacker': return '👤';
          case 'compromised': return '💀';
          case 'pivot': return '🔄';
          case 'target': return '🎯';
          default: return '🖥️';
        }
      });

    // Add labels
    node.append('text')
      .attr('dx', 25)
      .attr('dy', '.35em')
      .attr('font-size', '12px')
      .attr('fill', '#1f2937')
      .text((d) => d.name);

    // Add vulnerability count badge
    node.filter((d) => d.vulnerabilities && d.vulnerabilities > 0)
      .append('circle')
      .attr('cx', 15)
      .attr('cy', -15)
      .attr('r', 10)
      .attr('fill', '#dc2626')
      .attr('stroke', '#fff')
      .attr('stroke-width', 2);

    node.filter((d) => d.vulnerabilities && d.vulnerabilities > 0)
      .append('text')
      .attr('x', 15)
      .attr('y', -15)
      .attr('text-anchor', 'middle')
      .attr('dy', '.35em')
      .attr('font-size', '10px')
      .attr('fill', '#fff')
      .attr('font-weight', 'bold')
      .text((d) => d.vulnerabilities);

    // Update positions on tick
    simulation.on('tick', () => {
      link
        .attr('x1', (d: any) => d.source.x)
        .attr('y1', (d: any) => d.source.y)
        .attr('x2', (d: any) => d.target.x)
        .attr('y2', (d: any) => d.target.y);

      node.attr('transform', (d) => `translate(${d.x},${d.y})`);
    });

    // Drag functions
    function dragStarted(event: any, d: Node) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      d.fx = d.x;
      d.fy = d.y;
    }

    function dragged(event: any, d: Node) {
      d.fx = event.x;
      d.fy = event.y;
    }

    function dragEnded(event: any, d: Node) {
      if (!event.active) simulation.alphaTarget(0);
      d.fx = null;
      d.fy = null;
    }

    // Cleanup
    return () => {
      simulation.stop();
    };
  }, [nodes, links, width, height, onNodeClick, onNodeDoubleClick]);

  // Reset zoom
  const handleResetZoom = () => {
    if (svgRef.current && zoom) {
      d3.select(svgRef.current)
        .transition()
        .duration(750)
        .call(zoom.transform as any, d3.zoomIdentity);
    }
  };

  // Fit to screen
  const handleFitToScreen = () => {
    if (!svgRef.current || nodes.length === 0) return;

    const svg = d3.select(svgRef.current);
    const bounds = svg.node()?.getBBox();

    if (!bounds) return;

    const fullWidth = width;
    const fullHeight = height;
    const midX = bounds.x + bounds.width / 2;
    const midY = bounds.y + bounds.height / 2;

    const scale = 0.9 / Math.max(bounds.width / fullWidth, bounds.height / fullHeight);
    const translate = [fullWidth / 2 - scale * midX, fullHeight / 2 - scale * midY];

    if (zoom) {
      svg.transition()
        .duration(750)
        .call(
          zoom.transform as any,
          d3.zoomIdentity.translate(translate[0], translate[1]).scale(scale)
        );
    }
  };

  return (
    <div className="network-map-container" style={{ position: 'relative' }}>
      {/* Controls */}
      <div style={{
        position: 'absolute',
        top: 10,
        right: 10,
        zIndex: 10,
        display: 'flex',
        gap: '8px'
      }}>
        <button
          onClick={handleResetZoom}
          style={{
            padding: '8px 16px',
            backgroundColor: '#3b82f6',
            color: '#fff',
            border: 'none',
            borderRadius: '4px',
            cursor: 'pointer'
          }}
        >
          Reset Zoom
        </button>
        <button
          onClick={handleFitToScreen}
          style={{
            padding: '8px 16px',
            backgroundColor: '#10b981',
            color: '#fff',
            border: 'none',
            borderRadius: '4px',
            cursor: 'pointer'
          }}
        >
          Fit to Screen
        </button>
      </div>

      {/* SVG Canvas */}
      <svg
        ref={svgRef}
        style={{
          border: '1px solid #e5e7eb',
          borderRadius: '8px',
          backgroundColor: '#f9fafb'
        }}
      />

      {/* Node Info Panel */}
      {selectedNode && (
        <div style={{
          position: 'absolute',
          bottom: 10,
          left: 10,
          backgroundColor: '#fff',
          border: '1px solid #e5e7eb',
          borderRadius: '8px',
          padding: '16px',
          minWidth: '250px',
          boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 'bold' }}>
              {selectedNode.name}
            </h3>
            <button
              onClick={() => setSelectedNode(null)}
              style={{
                background: 'none',
                border: 'none',
                fontSize: '20px',
                cursor: 'pointer',
                color: '#6b7280'
              }}
            >
              ×
            </button>
          </div>
          <div style={{ marginTop: '12px', fontSize: '14px', color: '#6b7280' }}>
            <div><strong>Type:</strong> {selectedNode.type}</div>
            {selectedNode.ip && <div><strong>IP:</strong> {selectedNode.ip}</div>}
            {selectedNode.os && <div><strong>OS:</strong> {selectedNode.os}</div>}
            {selectedNode.vulnerabilities !== undefined && (
              <div><strong>Vulnerabilities:</strong> {selectedNode.vulnerabilities}</div>
            )}
          </div>
        </div>
      )}

      {/* Legend */}
      <div style={{
        position: 'absolute',
        top: 10,
        left: 10,
        backgroundColor: '#fff',
        border: '1px solid #e5e7eb',
        borderRadius: '8px',
        padding: '12px',
        fontSize: '12px'
      }}>
        <div style={{ fontWeight: 'bold', marginBottom: '8px' }}>Legend</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
          <div style={{ width: 16, height: 16, borderRadius: '50%', backgroundColor: '#8b5cf6' }} />
          <span>Attacker</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
          <div style={{ width: 16, height: 16, borderRadius: '50%', backgroundColor: '#3b82f6' }} />
          <span>Target</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
          <div style={{ width: 16, height: 16, borderRadius: '50%', backgroundColor: '#ef4444' }} />
          <span>Compromised</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <div style={{ width: 16, height: 16, borderRadius: '50%', backgroundColor: '#f59e0b' }} />
          <span>Pivot</span>
        </div>
      </div>
    </div>
  );
};

export default NetworkMap;

