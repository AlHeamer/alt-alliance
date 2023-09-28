# Alt Alliance

## Usage

Primary configuration should be done using a config yaml file, an example of which is provided in the repository `config.example.yaml`.
Checks can be overridden on the command line from those defined in the supplied config file checks will be set using `-check_flag`, and unset with`-check_flag=f`
```
Usage of ./alt-alliance:
  unset checks using -flag=f

  -char-exists
    	Check that the character exists in neucore
  -char-groups
    	Check at least one character has each neucore role
  -char-valid
    	Check that all alts in neucore have a valid esi token
  -corp-tax
    	Check that corp tax rate matches that set in config
  -corp-war
    	Check that corps are not war eligible
  -dry-run
    	Don't output to slack
  -f string
    	Config file to use (default "./config.yaml")
  -n	alias of -dry-run
  -notif-structure
    	Check CEO notifications for anchoring or onlining structures
  -notif-war
    	Check CEO notifications for changes in war eligibility status
  -q	Don't print the execution time footer to slack if there are no issues
```

## Building

### Requirements and Dependancies

* Golang 1.20
	- Additional go libraries/dependencies are listed in `go.mod`

### Manual Build

At this time, `neucore-api-go v0.0.0-20230618143013-6eda4be041a3` has a compile error in it that can be worked around with the following: 
``` bash
UTILS=$GOPATH/pkg/mod/github.com/bravecollective/neucore-api-go@v0.0.0-20230618143013-6eda4be041a3/utils.go
chmod +w $UTILS
cat <<EOT >> $UTILS

func isNil(i interface{}) bool {
	return IsNil(i)
}
EOT
chmod -w $UTILS
```

From the top level of the repository, run
``` bash
go build
```

You may want to build for different platforms, like `linux`, `windows`, `darwin` (macos), or architechtures; `amd64`, `arm64`. Trimming the binary size can be done by removing DWARF debugging info `-w`, GO symbols `-s`, and build machine paths `-trimpath`, you would want to run `go build -gcflags -trimpath=$PWD -ldflags "-s -w"`
``` bash
env GOOS=linux GOARCH=arm64 go build -gcflags -trimpath=$PWD -ldflags "-s -w"
```

### Build via Docker

alt-alliance can be built using the following docker command from the top level of the repository:
``` bash
docker run -v $PWD:/build golang:1.20 /bin/sh -c "cd /build; go build"
```

crosscompiled to other platforms (linux/arm64 for example)
``` bash
docker run -v $PWD:/build golang:1.20 /bin/sh -c "cd /build; env GOOS=linux GOARCH=arm64 go build -o aa_linux_arm64"
```

``` bash
docker run -v $PWD:/build golang:1.20 /bin/sh -c "cd /build; go build -gcflags -trimpath=/build -ldflags "-s -w""
```

for alternate docker images like alpine, check https://hub.docker.com/_/golang

## TODO

* Retry calls on error/timeout/etc.
* Cache endpoint calls

## EVEMail Markup

### Special Characters and HTML Tags

Eve supports several standard html tags and special characters:
* `<br>` (force a new line)
* `<b>bold text</b>`
* `<i>italic text</i>`
* `<u>underlined text</u>`
* `<font size="12" color="#b3ffffff">text size and colour</font>`
* `<a href="http://www.example.com">hyperlinks</a>`
* `&lt;` <
* `&gt;` >

#### Colours

Using the `font` tag, you can specify the colour of your text in the hex format `#AARRGGBB` This differs from standard HTML with the addition of `AA` for an alpha (transparency) value.
* Default text colour: `#b3ffffff`
* Type link colour: `#ffd98d00`

### Showinfo Links

You can also link to item types with a custom href of the following format:
``` html
<a href="showinfo:TypeID">Type Name</a>
```
eg. `<a href="showinfo:34">Tritanium</a>`

Some types also support linking a specific instance of that type in the format:
``` html
<a href="showinfo:TypeID//InstanceID">Specific Type Name</a>
```
eg. `<a href="showinfo:2//109299958">C C P</a>`

|   Type Name   | Type ID |   Type Name   | Type ID |
|---------------|--------:|---------------|--------:|
| Alliance      |   16159 | Astrahus      |   35832 |
| Asteroid Belt |      15 | Athanor       |   35835 |
| Character     |    1377 | Azbel         |   35826 |
| Constellation |       4 | Fortizar      |   35833 |
| Corporation   |       2 | Keepstar      |   35834 |
| Faction       |      30 | Raitaru       |   35825 |
| Moon          |      14 | Sotiyo        |   35827 |
| Region        |       3 | Tatara        |   35836 |
| Solar System  |       5 |               |         |

#### Additional Examples

``` html
<a href="showinfo:2//109299958">C C P</a>
<a href="showinfo:16159//434243723">C C P Alliance</a>
<a href="showinfo:1529//60003466">Jita IV - Moon 4 - Caldari Business Tribunal Bureau Offices</a>
<a href="showinfo:52678//60003760">Jita IV - Moon 4 - Caldari Navy Assembly Plant</a>
```
