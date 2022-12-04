import typescript from '@rollup/plugin-typescript'

export default [
	{
		input: ['src/index.ts'],
		output: {
			dir: './',
			format: 'es',
			sourcemap: false
		},
		plugins: [
			typescript({
				"compilerOptions": {
						"target": "es2022"
				}})
		]
	}
]
