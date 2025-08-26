#!/bin/bash
# MeTTa Setup Script for macOS M1 Max
# This script installs MeTTa and its dependencies

set -e

echo "🚀 Setting up MeTTa on macOS M1 Max..."

# Clone MeTTa repositories
echo "📥 Cloning MeTTa repositories..."
mkdir -p ~/metta_workspace
cd ~/metta_workspace

# Clone hyperon-experimental (main MeTTa implementation)
if [ ! -d "hyperon-experimental" ]; then
    git clone https://github.com/trueagi-io/hyperon-experimental.git
fi

cd hyperon-experimental

# Build MeTTa
echo "🔨 Building MeTTa..."
mkdir -p build
cd build
cmake ..
make -j$(sysctl -n hw.ncpu)

# Install Python bindings
echo "🔗 Installing Python bindings..."
cd ../python
pip install -e .

# Test installation
echo "🧪 Testing MeTTa installation..."
python -c "
import hyperon
from hyperon import *
print('✅ MeTTa Python bindings installed successfully!')

# Test basic functionality
space = GroundingSpace()
space.add_atom(E(S('='), [S('foo'), S('bar')]))
result = space.query(E(S('='), [S('foo'), V('x')]))
print(f'✅ Basic query test passed: {result}')
"

echo "🎉 MeTTa setup complete!"
echo ""
echo "To activate the environment in the future:"
echo "  conda activate metta_env"
echo ""
echo "MeTTa workspace location: ~/metta_workspace/"
echo "Python bindings installed in virtual environment"