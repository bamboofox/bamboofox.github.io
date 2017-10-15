# bamboofox.github.io

This blog is powered by [jekyll](http://jekyllrb.com/) and [jekyll-theme-H2O](https://github.com/kaeyleo/jekyll-theme-H2O)

## Get started

```bash
gem install jekyll bundler
git clone https://github.com/bamboofox/bamboofox.github.io
cd bamboofox.github.io/
bundle install
jekyll serve
```

Now browse to http://localhost:4000

## Writing a post

Access admin panel on http://localhost:4000/admin

Switch to `Posts` section and clink on `New post` button

Enter your post name on `Title`

### Metadata

press "New metadata field" to add a column in post header

- Add `post` into `layout` field

#### Club Course

- Add `club` into `tags` array
- Add `tutorial` into `categories` array

#### Write up

- Add `your_name` into `author` field
- Add `related_technique` into `tags` array(e.g., `pwn`, `ROP`, `buffer overflow`)
- Add `write-ups` into `categories` array

### Publish

1. Fork this repo
2. Working on your branch
3. Open a pull request
4. Once your pull request get merged, your post will be available on https://bamboofox.github.io/

**It takes time to build the github page**

**Grab a cup of coffee :coffee: and watch it**

## Docker support

You can use this container https://hub.docker.com/r/jekyll/jekyll/

```bash
docker pull jekyll/jekyll
docker run -it -p 127.0.0.1:4000:4000 jekyll/jekyll /bin/bash

# inside container
git clone https://github.com/bamboofox/bamboofox.github.io.git
cd bamboofox.github.io
bundle install
bundle exec jekyll serve --host 0.0.0.0
```
