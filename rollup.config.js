import typescript from '@rollup/plugin-typescript'
import tsconfig from './tsconfig.json' assert { type: 'json'}

export default [
	{
		input: ['src/index.ts'],
		output: {
			dir: './',
			format: 'es',
			sourcemap: false
		},
		plugins: [
			typescript(tsconfig)
		]
	}
]
