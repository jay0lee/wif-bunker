import re

with open('/Users/jay/Documents/wif-bunker/repo/.github/workflows/quick-test.yml', 'r') as f:
    content = f.read()

# Replace env vars
content = re.sub(
    r'      # OpenSSL \+ Python compile-from-source paths\n      OPENSSL_INSTALL_PATH: \$\{\{ github\.workspace \}\}/bin/ssl\n      OPENSSL_SOURCE_PATH: \$\{\{ github\.workspace \}\}/src/openssl\n      PYTHON_INSTALL_PATH: \$\{\{ github\.workspace \}\}/bin/python\n      PYTHON_SOURCE_PATH: \$\{\{ github\.workspace \}\}/src/cpython\n      OPENSSL_CONFIG_OPTS: no-fips no-docs no-shared -fPIC no-tests -O3',
    '      # Paths to pre-built OpenSSL + Python (from build-python-ssl.yml cache)\n      OPENSSL_INSTALL_PATH: ${{ github.workspace }}/bin/ssl\n      PYTHON_INSTALL_PATH: ${{ github.workspace }}/bin/python',
    content
)

# Replace compile section
compile_section_start = '      # ══════════════════════════════════════════════════════════════════════\n      # Compile OpenSSL + Python from source'
compile_section_end = 'python3 -c "import ssl; print(f\'Python ssl module OpenSSL: {ssl.OPENSSL_VERSION}\')"\n'

start_idx = content.find(compile_section_start)
end_idx = content.find(compile_section_end) + len(compile_section_end)

replacement = """      # ══════════════════════════════════════════════════════════════════════
      # Restore pre-built OpenSSL + Python from cache
      # Built daily by build-python-ssl.yml — restore-keys prefix match
      # falls back to the most recent successful build.
      # ══════════════════════════════════════════════════════════════════════

      - name: "Restore compiled OpenSSL + Python"
        if: needs.config.outputs.runner != 'hardware-tpm' && needs.config.outputs.runner != 'yubikey'
        uses: actions/cache/restore@cdf6c1fa76f9f475f3d7449005a359c84ca0f306 # v5.0.3
        id: cache-python-ssl
        with:
          path: |
            bin/ssl
            bin/python
          restore-keys: |
            python-ssl-${{ runner.os }}-${{ runner.arch }}-v1-
          fail-on-cache-miss: true

      - name: "Add compiled Python to PATH"
        if: needs.config.outputs.runner != 'hardware-tpm' && needs.config.outputs.runner != 'yubikey'
        shell: bash
        run: |
          if [[ "${RUNNER_OS}" == "Windows" ]]; then
            echo "${PYTHON_INSTALL_PATH}" >> "$GITHUB_PATH"
            echo "${PYTHON_INSTALL_PATH}/Scripts" >> "$GITHUB_PATH"
          else
            echo "${PYTHON_INSTALL_PATH}/bin" >> "$GITHUB_PATH"
            if [[ "${RUNNER_OS}" == "Linux" ]]; then
              echo "LD_LIBRARY_PATH=${PYTHON_INSTALL_PATH}/lib:${OPENSSL_INSTALL_PATH}/lib:${LD_LIBRARY_PATH}" >> $GITHUB_ENV
            elif [[ "${RUNNER_OS}" == "macOS" ]]; then
              echo "DYLD_LIBRARY_PATH=${PYTHON_INSTALL_PATH}/lib:${OPENSSL_INSTALL_PATH}/lib:${DYLD_LIBRARY_PATH}" >> $GITHUB_ENV
            fi
          fi

      - name: "Verify compiled Python + OpenSSL"
        if: needs.config.outputs.runner != 'hardware-tpm' && needs.config.outputs.runner != 'yubikey'
        shell: bash
        run: |
          echo "Python: $(python3 --version)"
          python3 -c "import ssl; print(f'Python ssl module OpenSSL: {ssl.OPENSSL_VERSION}')"
"""

if start_idx != -1 and end_idx != -1:
    content = content[:start_idx] + replacement + content[end_idx:]

with open('/Users/jay/Documents/wif-bunker/repo/.github/workflows/quick-test.yml', 'w') as f:
    f.write(content)
