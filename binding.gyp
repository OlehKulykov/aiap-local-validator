{
  'targets': [
    {
      'target_name': 'aiap-local-validator',
      'sources': [
        'src/validator.cpp',
        'src/validator_base64.cpp',
        'src/validator_date.cpp',
        'src/validator_exception.cpp',
        'src/validator_files.cpp'
      ],
      'cflags!': [ '-fno-exceptions' ],
      'cflags_cc!': [ '-fno-exceptions' ],
      'conditions': [
        ['OS=="mac"', {
          'xcode_settings': {
            'GCC_ENABLE_CPP_EXCEPTIONS': 'YES'
          }
        }]
      ]
    }
  ]
}
