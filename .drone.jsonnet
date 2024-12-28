local build(arch) = [{
  kind: 'pipeline',
  type: 'docker',
  name: arch,
  platform: {
    os: 'linux',
    arch: arch,
  },
  steps: [
  ] + (if arch == "amd64" then [
  {
      name: 'build-web',
      image: "node:20.9.0",
      commands: [
        'cd server/templates && make build && cd ../..',
        'cd webapp',
        'npm config set fetch-retry-mintimeout 200000',
        'npm config set fetch-retry-maxtimeout 1200000',
        'npm i',
        'npm run build',
        'cd channels',
        'mv dist client',
        'cd ../..',
        'tar -czf web-$DRONE_TAG.tar.gz -C webapp/channels client -C ../../server templates'
      ],
    },
   {
        name: "publish web",
        image: "plugins/github-release:1.0.0",
        settings: {
            api_key: {
                from_secret: "github_token"
            },
            files: "web-*.tar.gz",
            overwrite: true,
            file_exists: "overwrite"
        },
        when: {
            event: [ "tag" ]
        }
    }
   ] else []) + [

  {
      name: 'build-server',
      image: "golang:1.24.5",
      commands: [
        'cd server',
        'make setup-go-work',
        'make build-linux BUILD_NUMBER="$DRONE_TAG"',
        'make prepackaged-plugins',
        'rm -rf /usr/local/go',
        'rm -rf /usr/lib/gcc',
        'tar -czf server-' + arch + '-$DRONE_TAG.tar.gz bin/mattermost bin/mmctl fonts i18n prepackaged_plugins /usr /lib'
      ],
    },
    {
        name: "publish server",
        image: "plugins/github-release:1.0.0",
        settings: {
            api_key: {
                from_secret: "github_token"
            },
            files: "server/server-*.tar.gz",
            overwrite: true,
            file_exists: "overwrite"
        },
        when: {
            event: [ "tag" ]
        }
    }

  ],
  trigger: {
    event: [
      'push',
      'pull_request',
      'tag'
    ],
  },
  volumes: [
  ],
}];

build('amd64') +
build('arm64')
