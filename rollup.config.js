import uglify from 'rollup-plugin-uglify';

export default [
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
