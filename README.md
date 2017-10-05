# bamboofox.github.io

This blog use [jekyll](http://jekyllrb.com/) staic-site creator

## Get started

make sure you have [ruby install](https://www.ruby-lang.org/zh_tw/documentation/installation/)

```
gem install jekyll
bundle install
```

## Local start server

`bundle exec jekyll serve` It will start a server at `localhost:4000`

## Jekyll Admin

A plugin called `jekyll-admin` will be install when you type `bundle install`

This plugin allow you to edit file directly in your localhost server `localhost:4000/admin`

## Generate static site files

`bundle exec jekyll build` After build complete, all the files will be under `_site`

## Docker support

You can use this container https://hub.docker.com/r/jekyll/jekyll/

```
docker pull jekyll/jekyll
docker run -it -p 127.0.0.1:4000:4000 jekyll/jekyll /bin/bash

# inside container
git clone https://github.com/bamboofox/bamboofox.github.io.git
cd bamboofox.github.io
bundle install
bundle exec jekyll serve --host 0.0.0.0
```

Go to 127.0.0.1:4000/admin

## Contribute

If you use jekyll admin

press "New metadata field" to add a column in post header

Here is the sample post header

```
---
title: hello-world
layout: post
author: me
tags:
  - food
categories:
  - tutorial
---
```

`title` and `layout` are mandatory ( remember to add layout when you use jekyll admin )

`author` and `tags` and `categories` are optional
