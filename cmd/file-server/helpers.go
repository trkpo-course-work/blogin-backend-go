package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"path"
)

func (app *application) writeJSON(w http.ResponseWriter, status int, data interface{}, headers http.Header) error {
	js, err := json.Marshal(data)
	if err != nil {
		return err
	}
	js = append(js, '\n')

	for key, value := range headers {
		w.Header()[key] = value
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(js)

	return nil
}

func (app *application) savePicture(source io.Reader) (string, error) {
	file, err := ioutil.TempFile(app.config.PicturesPath, "*.jpg")
	if err != nil {
		return "", err
	}
	defer file.Close()

	if err := file.Chmod(0777); err != nil {
		return "", err
	}

	if _, err := io.Copy(file, source); err != nil {
		return "", err
	}

	return fmt.Sprintf("/%s", path.Base(file.Name())), nil
}
