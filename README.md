# jfrog-xray-prettifier


### Example Usage

```yaml
    - name: 'Build and push image'
      run: |
        TAG=${{ secrets.DOCKER_URL }}/${{ inputs.DOCKER_IMAGE_NAME }}:${{ inputs.DOCKER_VERSION }}
        docker build --build-arg DOCKER_URL=${{ secrets.DOCKER_URL }} ${{ inputs.DOCKER_ADD_ARGS }} -f ${{ inputs.DOCKER_FILE_PATH }} -t ${TAG} ${{ inputs.DOCKER_BUILD_DIR }}
        jfrog rt docker-push ${TAG} ${{ env.JFROG_DOCKER_REPO }}
        
        if [[ "${{ inputs.DOCKER_XRAY_SCAN }}" == true ]]; then
          jfrog rt bce
          jfrog rt bag
          jfrog rt build-publish
          BUILD_SCAN=true
          if [[ "$BUILD_SCAN" == "true" ]]; then
            ## Scan the build but write the results to a file so we can parse them later
            ##  The build is not failing here
            jfrog rt build-scan --fail=true >> ./xray-results.json || true
          fi
        fi
      env:
        JFROG_CLI_BUILD_NAME: ${{ inputs.JFROG_BUILD_NAME }}
    - name: generate-xray-report
      if: ${{ inputs.DOCKER_XRAY_SCAN }}
      id: generate-xray-report
      uses: mikemcallister-lnrisk/jfrog-xray-prettifier@v0.1.0
      with:
        ## The file that was written to in the previous step
        XRAY_RESULTS_JSON_FILE: ./xray-results.json
        BUILD_NAME: "${{ inputs.JFROG_BUILD_NAME }}"
        BUILD_NUMBER: ${{ github.run_number }}
        ## Boolean to determine if the build should fail if there are any violations
        FAIL_BUILD: ${{ inputs.DOCKER_XRAY_FAIL }}

        ISSUE_URL_TEMPLATE: "https://github.com/org/report/issues/new?assignees=&labels=approved%2Capplied&projects=&template=JFrog_exception_request.yml&title=batchr3+exception+request+{cve_id}+{build_name}/{build_number}&violation_id={violation_id}&build_name={build_name}&business_unit=BU&build_repository=my-build-info&build_version={build_version}&business_justification={possible_reason}"
        TEAMS_WEBHOOK: ${{ secrets.TEAMS_WEBHOOK }}
```