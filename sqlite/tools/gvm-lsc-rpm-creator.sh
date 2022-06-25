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

# This script generates an RPM package that creates a user for GVM
# local security checks.

#
# Variables
#

# Command line parameters
USERNAME=$1
PUBKEY_FILE=$2
TEMP_DIR=$3
OUTPUT_PATH=$4

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

# Constants
# Package data
PACKAGE_NAME="gvm-lsc-target-${USERNAME}"
PACKAGE_VERSION="0.5"
PACKAGE_RELEASE="1"
PACKAGE_NAME_VERSION="${PACKAGE_NAME}-${PACKAGE_VERSION}-${PACKAGE_RELEASE}"

USER_COMMENT="GVM Local Security Checks"
# specify in case characters reserved by grep are used
USER_COMMENT_GREP="GVM\\ Local\\ Security\\ Checks"

PACKAGE_BASE_DIR="${TEMP_DIR}/${PACKAGE_NAME_VERSION}"

# Build directories
BUILD_ROOT_DIR="${PACKAGE_BASE_DIR}/build"
HOME_SUBDIR="home/${USERNAME}"
HOME_DATA_DIR="${BUILD_ROOT_DIR}/${HOME_SUBDIR}"
SSH_DATA_DIR="${HOME_DATA_DIR}/.ssh"

# Spec file directory
SPEC_DIR="${TEMP_DIR}"

#
# Test dependencies
#
if [ -z "$(which fakeroot)" ]
then
  echo "fakeroot not found" >&2
  exit 1
fi

if [ -z "$(which rpmbuild)" ]
then
  echo "rpmbuild not found" >&2
  exit 1
fi

#
# Set up error handling
#
handle_error() {
  echo "RPM package generation failed" >&2
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

#
# Create spec file
#

# Create directory
mkdir -p "${SPEC_DIR}"

# Create spec file
SPEC_FILE="${SPEC_DIR}/${PACKAGE_NAME_VERSION}.spec"
{
  # Basic info
  echo "Name: ${PACKAGE_NAME}"
  echo "Version: ${PACKAGE_VERSION}"
  echo "Release: ${PACKAGE_RELEASE}"
  echo "Group: Application/Misc"
  echo "Summary: OpenVAS local security check preparation"
  echo "License: GPL2+"
  echo "BuildArch: noarch"
  # Put output in current directory
  echo "%define _rpmdir %(pwd)"

  # Create description section
  echo "%description"
  echo "This package prepares a system for GVM local security checks."
  echo "A user is created with a specific SSH authorized key."
  echo "The corresponding private key is located at the respective"
  echo "GVM installation."

  # Create files section
  echo "%files"
  echo "/${HOME_SUBDIR}"

  # Create "pre" section run before installation
  echo "%pre"
  echo "#!/bin/sh"
  echo "set -e  # abort on errors"
  echo "useradd -c \"${USER_COMMENT}\" -d /home/${USERNAME} -m -s /bin/bash ${USERNAME}"

  # Create "post" section run after installation
  echo "%post"
  echo "#!/bin/sh"
  echo "set -e  # abort on errors"
  echo "chown -R ${USERNAME}:${USERNAME} /home/${USERNAME}"
  echo "chmod 500 /home/${USERNAME}/.ssh"
  echo "chmod 400 /home/${USERNAME}/.ssh/authorized_keys"

  # Create "postun" section run after removal or on error
  echo "%postun"
  echo "#!/bin/sh"
  echo "# Remove user only if it was created by this package."
  echo "# The debian package will run the postun script in case of errors"
  echo "# (e.g. user already existed)."
  echo "# Delete the user only if /etc/passwd lists content that suggests"
  echo "# that the user was created by this package."
  #echo "set -e  # abort on errors"
  echo "grep \"${USERNAME}.*${USER_COMMENT_GREP}\" /etc/passwd && userdel -f ${USERNAME}"
} > "${SPEC_FILE}"

#
# Build package
#

# Build package
cd "$TEMP_DIR"
fakeroot -- rpmbuild --bb "${SPEC_FILE}" --buildroot "${BUILD_ROOT_DIR}"

# Move package to new destination
mv "${TEMP_DIR}/noarch/${PACKAGE_NAME_VERSION}.noarch.rpm" "${OUTPUT_PATH}"
