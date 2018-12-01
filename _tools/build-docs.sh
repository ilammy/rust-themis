#!/bin/sh
#
# Build API documentation for Themis.
#
# Unfortunately, rust-themis build requires native Themis library which is not
# available on docs.rs. Therefore we have to build our documentation ourselves.
#
# Usage:
#
#   git clone git@github.com:ilammy/rust-themis
#   cd rust-themis
#   git checkout gh-pages
#   _tools/build-docs.sh
#   git commit --all
#   git push
#
# You're done.

set -eu

# Set to "yes" in order to build documentation for master branch.
# Use anything else to build only published `themis_versions`.
build_master=yes
master_branch=master

# Root URL of the hosted documentation:
docs_root="https://rust-themis.ilammy.net"

# URL of the Themis repository:
themis_repo="https://github.com/ilammy/rust-themis"

# Published versions to document:
themis_versions="
0.0.2
0.0.1
"

if [ "$build_master" = "yes" ]
then
    themis_versions="master $themis_versions"
fi

mkdir -p _crates
mkdir -p _target

export CARGO_TARGET_DIR=$PWD/_target

retrieve_themis() {
    local version="$1"
    cd _crates
    if [ "$version" = "master" ]
    then
        checkout_themis_repo
    else
        download_themis_crate "$version"
    fi
    cd ..
}

checkout_themis_repo() {
    echo "Pulling master..."
    if [ ! -d "themis-master" ]
    then
        git init themis-master
    fi
    cd themis-master
    # We use such roundabout way in order to try keeping whatever repo is there
    # but enforce the current origin URL and checkout the latest master branch.
    git remote remove origin || true
    git remote add origin "$themis_repo"
    git fetch origin
    git checkout -f "origin/$master_branch"
    cd ..
}

download_themis_crate() {
    local version=$1
    if [ ! -d "themis-$version" ]
    then
        echo "Downloading $version..."
        curl --silent --location --output themis.tgz \
            "https://crates.io/api/v1/crates/themis/$version/download"
        tar xf themis.tgz
        rm themis.tgz
    fi
}

generate_header() {
    local version
    local current_version=$1
    echo "<div class=\"version-picker\"><p>"
    echo "Themis version:"
    for version in $themis_versions
    do
        local class
        local url="$docs_root/$version/themis/index.html"
        if [ "$version" = "$current_version" ]
        then
            class="current-version"
        else
            class="old-version"
        fi
        echo "<a href=\"$url\" class=\"$class\">$version</a>"
    done
    echo "</p></div>"
    echo "<div class=\"rustdoc-container\">"
}

generate_footer() {
    echo "</div>"
}

generate_css() {
    cat <<END
div.version-picker {
    color: #000;
    background-color: #fff;
    border-bottom: 1px solid #ddd;
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 32px;
    padding: 0.5em 1em;
    font-family: "Fira Sans", "Helvetica Neue", Helvetica, Arial, sans-serif;
    font-size: 0.8em;
    z-index: 999;
}

div.version-picker a {
    color: #4d76ae;
    margin-left: 0.5em;
}

div.version-picker a.current-version {
    font-weight: 800;
}

div.rustdoc-container {
    position: absolute;
    top: 32px;
    left: 0;
    right: 0;
    padding: 10px 15px 20px 15px;
    max-width: 1200px;
    text-align: left;
}

div.rustdoc-container nav.sidebar {
    padding-top: 32px;
}
END
}

document_themis() {
    local version=$1

    rm -rf "$version"

    echo "Updating $version..."
    retrieve_themis "$version"

    cd "_crates/themis-$version"

    generate_header "$version" > header.html
    generate_footer > footer.html
    generate_css > style.css

    echo "Documenting $version..."
    cargo clean --doc
    cargo rustdoc -- \
        --html-before-content header.html \
        --html-after-content footer.html \
        --extend-css style.css
    mv "$CARGO_TARGET_DIR/doc" "../../$version"

    rm header.html
    rm footer.html
    rm style.css

    cd ../..
}

for version in $themis_versions
do
    document_themis "$version"
done

latest_version=$(echo $themis_versions | awk '{ print $1 }')
rm -f latest && ln -s "$latest_version" latest
