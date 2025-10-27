import { useState } from 'react';
import { Filter, SortAsc, SortDesc, X } from 'lucide-react';

interface FilterOption {
  key: string;
  label: string;
  type: 'select' | 'text' | 'date';
  options?: { value: string; label: string }[];
}

interface SortOption {
  key: string;
  label: string;
}

interface FilterSortProps {
  filterOptions: FilterOption[];
  sortOptions: SortOption[];
  onFilterChange: (filters: Record<string, any>) => void;
  onSortChange: (sortBy: string, sortOrder: 'asc' | 'desc') => void;
}

export default function FilterSort({
  filterOptions,
  sortOptions,
  onFilterChange,
  onSortChange,
}: FilterSortProps) {
  const [showFilters, setShowFilters] = useState(false);
  const [filters, setFilters] = useState<Record<string, any>>({});
  const [sortBy, setSortBy] = useState<string>('');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc');

  const handleFilterChange = (key: string, value: any) => {
    const newFilters = { ...filters, [key]: value };
    setFilters(newFilters);
    onFilterChange(newFilters);
  };

  const handleClearFilter = (key: string) => {
    const newFilters = { ...filters };
    delete newFilters[key];
    setFilters(newFilters);
    onFilterChange(newFilters);
  };

  const handleClearAllFilters = () => {
    setFilters({});
    onFilterChange({});
  };

  const handleSortChange = (key: string) => {
    if (sortBy === key) {
      const newOrder = sortOrder === 'asc' ? 'desc' : 'asc';
      setSortOrder(newOrder);
      onSortChange(key, newOrder);
    } else {
      setSortBy(key);
      setSortOrder('asc');
      onSortChange(key, 'asc');
    }
  };

  const activeFilterCount = Object.keys(filters).filter(
    key => filters[key] !== '' && filters[key] !== undefined
  ).length;

  return (
    <div className="space-y-4">
      {/* Filter & Sort Controls */}
      <div className="flex items-center gap-3">
        <button
          onClick={() => setShowFilters(!showFilters)}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors ${
            showFilters || activeFilterCount > 0
              ? 'bg-cyan-500 text-white'
              : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
          }`}
        >
          <Filter className="w-4 h-4" />
          <span>Filters</span>
          {activeFilterCount > 0 && (
            <span className="px-2 py-0.5 bg-white text-cyan-500 rounded-full text-xs font-semibold">
              {activeFilterCount}
            </span>
          )}
        </button>

        <div className="flex items-center gap-2">
          <span className="text-sm text-gray-400">Sort by:</span>
          <select
            value={sortBy}
            onChange={(e) => handleSortChange(e.target.value)}
            className="px-3 py-2 bg-gray-700 text-white rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          >
            <option value="">None</option>
            {sortOptions.map((option) => (
              <option key={option.key} value={option.key}>
                {option.label}
              </option>
            ))}
          </select>
          {sortBy && (
            <button
              onClick={() => handleSortChange(sortBy)}
              className="p-2 bg-gray-700 text-white rounded-lg hover:bg-gray-600 transition-colors"
            >
              {sortOrder === 'asc' ? (
                <SortAsc className="w-4 h-4" />
              ) : (
                <SortDesc className="w-4 h-4" />
              )}
            </button>
          )}
        </div>

        {activeFilterCount > 0 && (
          <button
            onClick={handleClearAllFilters}
            className="ml-auto text-sm text-gray-400 hover:text-white transition-colors"
          >
            Clear all filters
          </button>
        )}
      </div>

      {/* Filter Panel */}
      {showFilters && (
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filterOptions.map((option) => (
              <div key={option.key} className="space-y-2">
                <label className="block text-sm font-medium text-gray-300">
                  {option.label}
                </label>
                <div className="relative">
                  {option.type === 'select' && option.options ? (
                    <select
                      value={filters[option.key] || ''}
                      onChange={(e) => handleFilterChange(option.key, e.target.value)}
                      className="w-full px-3 py-2 bg-gray-700 text-white rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                    >
                      <option value="">All</option>
                      {option.options.map((opt) => (
                        <option key={opt.value} value={opt.value}>
                          {opt.label}
                        </option>
                      ))}
                    </select>
                  ) : option.type === 'date' ? (
                    <input
                      type="date"
                      value={filters[option.key] || ''}
                      onChange={(e) => handleFilterChange(option.key, e.target.value)}
                      className="w-full px-3 py-2 bg-gray-700 text-white rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                    />
                  ) : (
                    <input
                      type="text"
                      value={filters[option.key] || ''}
                      onChange={(e) => handleFilterChange(option.key, e.target.value)}
                      placeholder={`Filter by ${option.label.toLowerCase()}`}
                      className="w-full px-3 py-2 bg-gray-700 text-white rounded-lg border border-gray-600 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                    />
                  )}
                  {filters[option.key] && (
                    <button
                      onClick={() => handleClearFilter(option.key)}
                      className="absolute right-2 top-1/2 -translate-y-1/2 p-1 text-gray-400 hover:text-white transition-colors"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Active Filters */}
      {activeFilterCount > 0 && (
        <div className="flex flex-wrap gap-2">
          {Object.entries(filters)
            .filter(([_, value]) => value !== '' && value !== undefined)
            .map(([key, value]) => {
              const option = filterOptions.find((opt) => opt.key === key);
              return (
                <div
                  key={key}
                  className="flex items-center gap-2 px-3 py-1 bg-cyan-500/20 text-cyan-400 rounded-full text-sm"
                >
                  <span>
                    {option?.label}: {value}
                  </span>
                  <button
                    onClick={() => handleClearFilter(key)}
                    className="hover:text-cyan-300 transition-colors"
                  >
                    <X className="w-3 h-3" />
                  </button>
                </div>
              );
            })}
        </div>
      )}
    </div>
  );
}

