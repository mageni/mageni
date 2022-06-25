#!/bin/bash
# Copyright (C) 2018 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

# This script generates a Debian package that creates a user for GVM
# local security checks.

#
# Variables
#

# Command line parameters
USERNAME="$1"
PUBKEY_FILE="$2"
TEMP_DIR="$3"
OUTPUT_PATH=$4
MAINTAINER_EMAIL="$5"

if [ -z "${USERNAME}" ]
then
  echo "No username given" >&2
  exit 1
fi

if [ -z "${PUBKEY_FILE}" ]
then
  echo "No pubkey path given" >&2
  exit 1
fi

if [ -z "${TEMP_DIR}" ]
then
  echo "No temp dir path given" >&2
  exit 1
fi

if [ -z "${OUTPUT_PATH}" ]
then
  echo "No output path given" >&2
  exit 1
fi

if [ -z "${MAINTAINER_EMAIL}" ]
then
  MAINTAINER_HOSTNAME="$(hostname)"
  if [ -z "$HOSTNAME" ]
  then
    MAINTAINER_HOSTNAME="localhost"
  fi
  MAINTAINER_EMAIL="admin@${MAINTAINER_HOSTNAME}"
fi

# Constants
# Package data
PACKAGE_NAME="gvm-lsc-target-${USERNAME}"
PACKAGE_VERSION="0.5-1"
PACKAGE_NAME_VERSION="${PACKAGE_NAME}_${PACKAGE_VERSION}"
MAINTAINER="Greenbone Vulnerability Manager  <${MAINTAINER_EMAIL}>"
PACKAGE_DATE=$(date "+%a, %d %b %Y %H:%M:%S %z")

USER_COMMENT="GVM Local Security Checks"
USER_COMMENT_GREP="GVM\\ Local\\ Security\\ Checks"

# Paths
PACKAGE_BASE_DIR="${TEMP_DIR}/${PACKAGE_NAME_VERSION}"

# Data paths
DATA_DIR="${PACKAGE_BASE_DIR}"
HOME_SUBDIR="home/${USERNAME}"
HOME_DATA_DIR="${DATA_DIR}/${HOME_SUBDIR}"
SSH_DATA_DIR="${HOME_DATA_DIR}/.ssh"
DOC_SUBDIR="usr/share/doc/${PACKAGE_NAME}"
DOC_DATA_DIR="${DATA_DIR}/${DOC_SUBDIR}"

# Control file path
CONTROL_DIR="${PACKAGE_BASE_DIR}/DEBIAN"

#
# Test dependencies
#
if [ -z "$(which dpkg)" ]
then
  echo "dpkg not found" >&2
  exit 1
fi

if [ -z "$(which fakeroot)" ]
then
  echo "fakeroot not found" >&2
  exit 1
fi

if [ -z "$(which md5sum)" ]
then
  echo "md5sum not found" >&2
  exit 1
fi

#
# Set up error handling
#
handle_error() {
  echo "DEB package generation failed" >&2
  exit 1
}
trap handle_error ERR

#
# Create data files
#

# Create .ssh directory
mkdir -p "${SSH_DATA_DIR}"

# Copy public key
AUTH_KEYS_FILE="${SSH_DATA_DIR}/authorized_keys"
cp "${PUBKEY_FILE}" "${AUTH_KEYS_FILE}"

# Create doc directory
mkdir -p "${DOC_DATA_DIR}"

# Create Changelog
cd "${DOC_DATA_DIR}"
CHANGELOG_FILE="${DOC_DATA_DIR}/changelog.Debian"
{
  echo "${PACKAGE_NAME} (${PACKAGE_VERSION}) experimental; urgency=low"
  echo ""
  echo "  * Automatically generated local security check credential package"
  echo "  "
  echo ""
  echo " -- ${MAINTAINER}  ${PACKAGE_DATE}"
} > "${CHANGELOG_FILE}"

# Compress Changelog
gzip -f --best "${CHANGELOG_FILE}"
CHANGELOG_FILE="${CHANGELOG_FILE}.gz"

# Create Copyright info
COPYRIGHT_FILE="${DOC_DATA_DIR}/copyright"
{
  echo "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/"
  echo ""
  echo "Files: *"
  echo "Copyright: 2018 Greenbone Networks GmbH"
  echo "License: GPL-2+ (/usr/share/common-licenses/GPL-2)"
} > "${COPYRIGHT_FILE}"

# Create data archive
cd "${DATA_DIR}"
tar -acf "../data.tar.xz" "${HOME_SUBDIR}" "${DOC_SUBDIR}" -C "${DATA_DIR}"


#
# Create control files
#

# Create directory
mkdir -p "${CONTROL_DIR}"
chmod "0755" "${CONTROL_DIR}"

# Create "control" file
CONTROL_FILE="${CONTROL_DIR}/control"
{
  echo "Package: ${PACKAGE_NAME}"
  echo "Version: ${PACKAGE_VERSION}"
  echo "Maintainer: ${MAINTAINER}"
  echo "Priority: optional"
  echo "Architecture: all"
  echo "Description: GVM local security check preparation"
  echo " This package prepares a system for GVM local security checks."
  echo " A user is created with a specific SSH authorized key."
  echo " The corresponding private key is located at the respective"
  echo " GVM installation."
} > "${CONTROL_FILE}"

# Create "preinst" file run before installation
PREINST_FILE="${CONTROL_DIR}/preinst"
touch "${PREINST_FILE}"
chmod "0755" "${PREINST_FILE}"
{
  echo "#!/bin/sh"
  echo "set -e  # abort on errors"
  echo "useradd -c \"${USER_COMMENT}\" -d /home/${USERNAME} -m -s /bin/bash ${USERNAME}"
} > "${PREINST_FILE}"

# Create "postinst" file run after installation
POSTINST_FILE="${CONTROL_DIR}/postinst"
touch "${POSTINST_FILE}"
chmod "0755" "${POSTINST_FILE}"
{
  echo "#!/bin/sh"
  echo "set -e  # abort on errors"
  echo "chown -R ${USERNAME}:${USERNAME} /home/${USERNAME}"
  echo "chmod 500 /home/${USERNAME}/.ssh"
  echo "chmod 400 /home/${USERNAME}/.ssh/authorized_keys"
} > "${POSTINST_FILE}"

# Create "postinst" file run after removal or on error
POSTRM_FILE="${CONTROL_DIR}/postrm"
touch "${POSTRM_FILE}"
chmod "0755" "${POSTRM_FILE}"
{
  echo "#!/bin/sh"
  echo "# Remove user only if it was created by this package."
  echo "# The debian package will run the postun script in case of errors"
  echo "# (e.g. user already existed)."
  echo "# Delete the user only if /etc/passwd lists content that suggests"
  echo "# that the user was created by this package."
  # echo "set -e  # abort on errors"
  echo "grep \"${USERNAME}.*${USER_COMMENT_GREP}\" /etc/passwd && userdel -fr ${USERNAME}"
} > "${POSTRM_FILE}"

# Calculate md5 checksums
MD5SUMS_FILE="${CONTROL_DIR}/md5sums"
cd "${DATA_DIR}"
{
  md5sum "${HOME_SUBDIR}/.ssh/authorized_keys"
  md5sum "${DOC_SUBDIR}/changelog.Debian.gz"
  md5sum "${DOC_SUBDIR}/copyright"
} > "${MD5SUMS_FILE}"

#
# Build package
#

# Combine into .deb file
cd "${TEMP_DIR}"
fakeroot -- dpkg --build "${PACKAGE_NAME_VERSION}" "${OUTPUT_PATH}"
