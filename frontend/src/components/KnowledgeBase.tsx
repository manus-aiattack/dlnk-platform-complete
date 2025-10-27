import React, { useState, useEffect } from 'react';
import { Book, Search, Tag, Star, ExternalLink, Code, Shield } from 'lucide-react';
import { api } from '../services/api';

interface Technique {
  id: string;
  name: string;
  category: string;
  description: string;
  difficulty: 'easy' | 'medium' | 'hard';
  tags: string[];
  code?: string;
  references: string[];
  successRate: number;
  usageCount: number;
}

interface Exploit {
  id: string;
  cve?: string;
  name: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  platforms: string[];
  code: string;
  references: string[];
}

export const KnowledgeBase: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'techniques' | 'exploits'>('techniques');
  const [techniques, setTechniques] = useState<Technique[]>([]);
  const [exploits, setExploits] = useState<Exploit[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [selectedItem, setSelectedItem] = useState<Technique | Exploit | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadData();
  }, [activeTab]);

  const loadData = async () => {
    try {
      setLoading(true);
      if (activeTab === 'techniques') {
        const response = await api.get('/api/knowledge/techniques');
        setTechniques(response.data);
      } else {
        const response = await api.get('/api/knowledge/exploits');
        setExploits(response.data);
      }
    } catch (error) {
      console.error('Failed to load knowledge base:', error);
    } finally {
      setLoading(false);
    }
  };

  const filteredTechniques = techniques.filter(t => {
    const matchesSearch = t.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         t.description.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesCategory = selectedCategory === 'all' || t.category === selectedCategory;
    return matchesSearch && matchesCategory;
  });

  const filteredExploits = exploits.filter(e => {
    const matchesSearch = e.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         e.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         (e.cve && e.cve.toLowerCase().includes(searchTerm.toLowerCase()));
    return matchesSearch;
  });

  const categories = Array.from(new Set(techniques.map(t => t.category)));

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'easy': return 'text-green-500 bg-green-500/10';
      case 'medium': return 'text-yellow-500 bg-yellow-500/10';
      case 'hard': return 'text-red-500 bg-red-500/10';
      default: return 'text-gray-500 bg-gray-500/10';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'low': return 'text-blue-500 bg-blue-500/10';
      case 'medium': return 'text-yellow-500 bg-yellow-500/10';
      case 'high': return 'text-orange-500 bg-orange-500/10';
      case 'critical': return 'text-red-500 bg-red-500/10';
      default: return 'text-gray-500 bg-gray-500/10';
    }
  };

  return (
    <div className="flex h-full bg-white dark:bg-gray-800 rounded-lg shadow-lg">
      {/* Sidebar */}
      <div className="w-1/3 border-r border-gray-200 dark:border-gray-700 flex flex-col">
        {/* Header */}
        <div className="p-4 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center gap-2 mb-4">
            <Book className="w-5 h-5 text-blue-500" />
            <h2 className="text-xl font-bold text-gray-900 dark:text-white">
              Knowledge Base
            </h2>
          </div>

          {/* Tabs */}
          <div className="flex gap-2">
            <button
              onClick={() => setActiveTab('techniques')}
              className={`flex-1 px-4 py-2 rounded-lg font-medium transition-colors ${
                activeTab === 'techniques'
                  ? 'bg-blue-500 text-white'
                  : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300'
              }`}
            >
              Techniques
            </button>
            <button
              onClick={() => setActiveTab('exploits')}
              className={`flex-1 px-4 py-2 rounded-lg font-medium transition-colors ${
                activeTab === 'exploits'
                  ? 'bg-blue-500 text-white'
                  : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300'
              }`}
            >
              Exploits
            </button>
          </div>
        </div>

        {/* Search and filters */}
        <div className="p-4 space-y-3 border-b border-gray-200 dark:border-gray-700">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
            />
          </div>

          {activeTab === 'techniques' && (
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
            >
              <option value="all">All Categories</option>
              {categories.map(cat => (
                <option key={cat} value={cat}>{cat}</option>
              ))}
            </select>
          )}
        </div>

        {/* List */}
        <div className="flex-1 overflow-y-auto p-4 space-y-2">
          {loading ? (
            <div className="flex items-center justify-center h-full">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
            </div>
          ) : activeTab === 'techniques' ? (
            filteredTechniques.map(technique => (
              <div
                key={technique.id}
                onClick={() => setSelectedItem(technique)}
                className={`p-3 rounded-lg cursor-pointer transition-colors ${
                  selectedItem?.id === technique.id
                    ? 'bg-blue-500/20 border-2 border-blue-500'
                    : 'bg-gray-50 dark:bg-gray-700 hover:bg-gray-100 dark:hover:bg-gray-600'
                }`}
              >
                <div className="flex items-start justify-between mb-2">
                  <h3 className="font-semibold text-gray-900 dark:text-white">
                    {technique.name}
                  </h3>
                  <span className={`px-2 py-1 text-xs font-medium rounded ${getDifficultyColor(technique.difficulty)}`}>
                    {technique.difficulty}
                  </span>
                </div>
                <p className="text-sm text-gray-600 dark:text-gray-400 line-clamp-2 mb-2">
                  {technique.description}
                </p>
                <div className="flex items-center gap-2 text-xs text-gray-500 dark:text-gray-400">
                  <Star className="w-3 h-3" />
                  <span>{technique.successRate}% success</span>
                  <span>•</span>
                  <span>{technique.usageCount} uses</span>
                </div>
              </div>
            ))
          ) : (
            filteredExploits.map(exploit => (
              <div
                key={exploit.id}
                onClick={() => setSelectedItem(exploit)}
                className={`p-3 rounded-lg cursor-pointer transition-colors ${
                  selectedItem?.id === exploit.id
                    ? 'bg-blue-500/20 border-2 border-blue-500'
                    : 'bg-gray-50 dark:bg-gray-700 hover:bg-gray-100 dark:hover:bg-gray-600'
                }`}
              >
                <div className="flex items-start justify-between mb-2">
                  <div>
                    <h3 className="font-semibold text-gray-900 dark:text-white">
                      {exploit.name}
                    </h3>
                    {exploit.cve && (
                      <span className="text-xs text-blue-500">{exploit.cve}</span>
                    )}
                  </div>
                  <span className={`px-2 py-1 text-xs font-medium rounded ${getSeverityColor(exploit.severity)}`}>
                    {exploit.severity}
                  </span>
                </div>
                <p className="text-sm text-gray-600 dark:text-gray-400 line-clamp-2">
                  {exploit.description}
                </p>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Detail view */}
      <div className="flex-1 flex flex-col">
        {selectedItem ? (
          <>
            <div className="p-6 border-b border-gray-200 dark:border-gray-700">
              <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">
                {selectedItem.name}
              </h2>
              {'cve' in selectedItem && selectedItem.cve && (
                <span className="inline-block px-3 py-1 bg-blue-500/10 text-blue-500 rounded-lg font-mono text-sm mb-3">
                  {selectedItem.cve}
                </span>
              )}
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                {selectedItem.description}
              </p>

              {/* Metadata */}
              <div className="flex flex-wrap gap-4 text-sm">
                {'difficulty' in selectedItem && (
                  <div className="flex items-center gap-2">
                    <Shield className="w-4 h-4 text-gray-400" />
                    <span className="text-gray-600 dark:text-gray-400">Difficulty:</span>
                    <span className={`px-2 py-1 rounded ${getDifficultyColor(selectedItem.difficulty)}`}>
                      {selectedItem.difficulty}
                    </span>
                  </div>
                )}
                {'severity' in selectedItem && (
                  <div className="flex items-center gap-2">
                    <Shield className="w-4 h-4 text-gray-400" />
                    <span className="text-gray-600 dark:text-gray-400">Severity:</span>
                    <span className={`px-2 py-1 rounded ${getSeverityColor(selectedItem.severity)}`}>
                      {selectedItem.severity}
                    </span>
                  </div>
                )}
              </div>

              {/* Tags */}
              {'tags' in selectedItem && selectedItem.tags.length > 0 && (
                <div className="flex flex-wrap gap-2 mt-4">
                  {selectedItem.tags.map(tag => (
                    <span key={tag} className="px-2 py-1 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded text-sm">
                      #{tag}
                    </span>
                  ))}
                </div>
              )}
            </div>

            {/* Code section */}
            {(('code' in selectedItem && selectedItem.code) || selectedItem.code) && (
              <div className="flex-1 overflow-y-auto p-6">
                <div className="flex items-center gap-2 mb-3">
                  <Code className="w-5 h-5 text-blue-500" />
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                    Implementation
                  </h3>
                </div>
                <pre className="bg-gray-900 text-gray-100 p-4 rounded-lg overflow-x-auto">
                  <code>{selectedItem.code}</code>
                </pre>
              </div>
            )}

            {/* References */}
            {selectedItem.references.length > 0 && (
              <div className="p-6 border-t border-gray-200 dark:border-gray-700">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3">
                  References
                </h3>
                <div className="space-y-2">
                  {selectedItem.references.map((ref, index) => (
                    <a
                      key={index}
                      href={ref}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-2 text-blue-500 hover:text-blue-600 transition-colors"
                    >
                      <ExternalLink className="w-4 h-4" />
                      <span className="text-sm">{ref}</span>
                    </a>
                  ))}
                </div>
              </div>
            )}
          </>
        ) : (
          <div className="flex items-center justify-center h-full text-gray-500 dark:text-gray-400">
            Select an item to view details
          </div>
        )}
      </div>
    </div>
  );
};

export default KnowledgeBase;

