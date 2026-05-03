'use client';

import { useState, useEffect } from 'react';
import { Search, Filter, Package, Building, Tag, AlertCircle } from 'lucide-react';

interface Category {
  name: string;
  count: number;
}

interface Component {
  id: number;
  name: string;
  component_id: string;
  vendor_name: string | null;
  category: string;
  product_version: string | null;
  ecosystem: string | null;
  recognition_support: string;
  vuln_count: number;
}

const DEFAULT_CATEGORIES = [
  "云平台设备",
  "工控设备",
  "应用服务",
  "服务器设备",
  "互联网设备",
  "移动设备",
  "中间件",
  "操作系统",
  "数据库",
  "物联网设备",
  "开发语言",
  "开发框架",
  "网络设备",
  "内网设备",
  "网络安全设备",
  "终端设备",
  "未知"
];

export default function ComponentsPage() {
  const [categories, setCategories] = useState<Category[]>([]);
  const [components, setComponents] = useState<Component[]>([]);
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [searchKeyword, setSearchKeyword] = useState('');
  const [vendorFilter, setVendorFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [showFilters, setShowFilters] = useState(false);

  useEffect(() => {
    fetchCategories();
    fetchComponents();
  }, [selectedCategory, searchKeyword, vendorFilter, page]);

  const fetchCategories = async () => {
    try {
      const response = await fetch('/api/v1/components/categories');
      if (response.ok) {
        const data = await response.json();
        setCategories(data.categories || []);
      }
    } catch (error) {
      console.error('Failed to fetch categories:', error);
      setCategories(DEFAULT_CATEGORIES.map(name => ({ name, count: 0 })));
    }
  };

  const fetchComponents = async () => {
    setLoading(true);
    try {
      let url = `/api/v1/components/list?page=${page}&page_size=20`;
      if (selectedCategory) {
        url += `&category=${encodeURIComponent(selectedCategory)}`;
      }
      if (searchKeyword) {
        url += `&keyword=${encodeURIComponent(searchKeyword)}`;
      }
      if (vendorFilter) {
        url += `&vendor=${encodeURIComponent(vendorFilter)}`;
      }

      const response = await fetch(url);
      if (response.ok) {
        const data = await response.json();
        setComponents(data.data || []);
        setTotal(data.total || 0);
      }
    } catch (error) {
      console.error('Failed to fetch components:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
  };

  const handleCategoryClick = (categoryName: string) => {
    setSelectedCategory(selectedCategory === categoryName ? null : categoryName);
    setPage(1);
  };

  const handleClearFilters = () => {
    setSelectedCategory(null);
    setSearchKeyword('');
    setVendorFilter('');
    setPage(1);
  };

  const totalPages = Math.ceil(total / 20);

  return (
    <div className="min-h-screen bg-background">
      <div className="container mx-auto px-4 py-8">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-3xl font-bold mb-2">组件信息</h1>
            <p className="text-muted-foreground">
              共 {total.toLocaleString()} 个组件
            </p>
          </div>
          <button
            onClick={() => setShowFilters(!showFilters)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg border transition-colors ${
              showFilters ? 'bg-primary text-white' : 'bg-muted hover:bg-accent'
            }`}
          >
            <Filter className="h-4 w-4" />
            筛选
          </button>
        </div>

        {showFilters && (
          <div className="bg-card border rounded-xl p-4 mb-6">
            <form onSubmit={handleSearch} className="flex flex-wrap gap-4">
              <div className="flex-1 min-w-[200px]">
                <label className="block text-sm font-medium mb-2">关键词搜索</label>
                <input
                  type="text"
                  value={searchKeyword}
                  onChange={(e) => setSearchKeyword(e.target.value)}
                  placeholder="输入组件名称或厂商..."
                  className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50"
                />
              </div>
              <div className="min-w-[200px]">
                <label className="block text-sm font-medium mb-2">厂商筛选</label>
                <input
                  type="text"
                  value={vendorFilter}
                  onChange={(e) => setVendorFilter(e.target.value)}
                  placeholder="输入厂商名称..."
                  className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50"
                />
              </div>
              <div className="flex items-end gap-2">
                <button
                  type="submit"
                  className="px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary/90"
                >
                  <Search className="h-4 w-4 inline" />
                  搜索
                </button>
                <button
                  type="button"
                  onClick={handleClearFilters}
                  className="px-4 py-2 bg-muted rounded-lg hover:bg-accent"
                >
                  清除筛选
                </button>
              </div>
            </form>
          </div>
        )}

        <div className="flex gap-6">
          <div className="w-64 shrink-0">
            <div className="bg-card border rounded-xl p-4 sticky top-8">
              <h2 className="font-semibold mb-4 flex items-center gap-2">
                <Package className="h-5 w-5" />
                组件分类
              </h2>
              <ul className="space-y-1">
                <li>
                  <button
                    onClick={() => { setSelectedCategory(null); setPage(1); }}
                    className={`w-full text-left px-3 py-2 rounded-lg transition-colors flex justify-between items-center ${
                      selectedCategory === null ? 'bg-primary text-white' : 'hover:bg-muted'
                    }`}
                  >
                    <span>全部</span>
                    <span className="text-xs opacity-70">{total.toLocaleString()}</span>
                  </button>
                </li>
                {categories.map((category) => (
                  <li key={category.name}>
                    <button
                      onClick={() => handleCategoryClick(category.name)}
                      className={`w-full text-left px-3 py-2 rounded-lg transition-colors flex justify-between items-center ${
                        selectedCategory === category.name ? 'bg-primary text-white' : 'hover:bg-muted'
                      }`}
                    >
                      <span>{category.name}</span>
                      <span className="text-xs opacity-70">{category.count}</span>
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          <div className="flex-1">
            {loading ? (
              <div className="flex items-center justify-center py-16">
                <div className="animate-spin h-8 w-8 border-2 border-primary border-t-transparent rounded-full"></div>
              </div>
            ) : components.length === 0 ? (
              <div className="text-center py-16">
                <AlertCircle className="h-16 w-16 mx-auto text-muted-foreground mb-4" />
                <p className="text-lg font-medium">未找到匹配的组件</p>
                <p className="text-muted-foreground mt-2">尝试调整筛选条件</p>
              </div>
            ) : (
              <>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {components.map((component) => (
                    <div
                      key={component.id}
                      className="bg-card border rounded-xl p-5 hover:border-primary/50 transition-colors"
                    >
                      <div className="flex items-start justify-between mb-3">
                        <div>
                          <h3 className="font-semibold text-lg mb-1">{component.name}</h3>
                          <code className="text-xs text-muted-foreground">{component.component_id}</code>
                        </div>
                        {component.vuln_count > 0 && (
                          <span className="shrink-0 px-2 py-1 bg-red-100 dark:bg-red-900 text-red-700 dark:text-red-300 rounded text-xs font-medium">
                            {component.vuln_count} 漏洞
                          </span>
                        )}
                      </div>

                      <div className="flex flex-wrap gap-2 mb-3">
                        <span className="px-2 py-1 bg-muted rounded text-xs flex items-center gap-1">
                          <Tag className="h-3 w-3" />
                          {component.category}
                        </span>
                        {component.ecosystem && (
                          <span className="px-2 py-1 bg-muted rounded text-xs">
                            {component.ecosystem}
                          </span>
                        )}
                        {component.product_version && (
                          <span className="px-2 py-1 bg-muted rounded text-xs">
                            版本: {component.product_version}
                          </span>
                        )}
                      </div>

                      <div className="flex items-center justify-between">
                        {component.vendor_name ? (
                          <div className="flex items-center gap-2 text-sm">
                            <Building className="h-4 w-4 text-muted-foreground" />
                            <span>{component.vendor_name}</span>
                          </div>
                        ) : (
                          <div className="text-sm text-muted-foreground">
                            厂商: 未知
                          </div>
                        )}
                        <span className={`text-xs px-2 py-1 rounded ${
                          component.recognition_support === '暂不支持识别'
                            ? 'bg-gray-100 text-gray-600'
                            : 'bg-green-100 text-green-600'
                        }`}>
                          {component.recognition_support}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>

                <div className="mt-8 flex items-center justify-center gap-2">
                  <button
                    onClick={() => setPage(Math.max(1, page - 1))}
                    disabled={page === 1}
                    className="px-4 py-2 border rounded-lg hover:bg-muted disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    上一页
                  </button>
                  <span className="text-muted-foreground">
                    第 {page} / {totalPages} 页
                  </span>
                  <button
                    onClick={() => setPage(Math.min(totalPages, page + 1))}
                    disabled={page === totalPages}
                    className="px-4 py-2 border rounded-lg hover:bg-muted disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    下一页
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
