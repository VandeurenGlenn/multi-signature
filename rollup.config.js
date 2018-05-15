import uglify from 'rollup-plugin-uglify';

export default [
	// ES module version, for modern browsers
	{
		input: ['src/index.js'],
		output: {
			dir: './',
			format: 'cjs',
			sourcemap: false
		},
		experimentalCodeSplitting: true,
		experimentalDynamicImport: true,
    plugins: [
      uglify()
    ]
	}
]
