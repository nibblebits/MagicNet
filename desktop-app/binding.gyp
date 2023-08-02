{
	"targets": [
		{
			"target_name": "magicnet",
			"sources": ["src/cpp/magicnetext.cpp"],
			"include_dirs": ["<!(node -e \"require('nan')\")", "../lib/include"],
            "libraries": [
				"-L../lib/include -lmagicnet" 
			],
            
			'cflags': ['-g', '-fPIC', '-fpermissive'],
			'cflags!': ['-fno-exceptions'],
			'cflags_cc!': ['-fno-exceptions'],
			'xcode_settings': {
				'GCC_ENABLE_CPP_EXCEPTIONS': 'YES',
				'GCC_ENABLE_CPP_RTTI': 'YES',
				'MACOSX_DEPLOYMENT_TARGET': '10.7', 
			},
		}
	]
}