package main

import (
	"fmt"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/SergeyKozhin/blogin-auth/internal/data/models"
)

func (app *application) uploadPicture(w http.ResponseWriter, r *http.Request) {
	multipartFile, headers, err := r.FormFile("file")
	if err != nil {
		app.badRequestResponse(w, r, err)
		return
	}
	defer multipartFile.Close()

	if headers.Size > app.config.MaxFileSize {
		app.fileTooBigResponse(w, r)
		return
	}

	fileName, err := app.savePicture(multipartFile)
	if err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}

	picture := &models.Picture{
		Path: fileName,
	}
	if err := app.pictures.Add(r.Context(), picture); err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}

	resp := &struct {
		ID int64 `json:"id,omitempty"`
	}{
		ID: picture.ID,
	}
	if err := app.writeJSON(w, http.StatusCreated, resp, nil); err != nil {
		app.serverErrorResponse(w, r, err)
	}
}

func (app *application) downloadPicture(w http.ResponseWriter, r *http.Request) {
	picture, ok := r.Context().Value(contextKeyPicture).(*models.Picture)
	if !ok {
		app.serverErrorResponse(w, r, ErrCantRetrieveEntity)
		return
	}

	file, err := os.Open(path.Join(app.config.PicturesPath, picture.Path))
	if err != nil {
		switch {
		case os.IsNotExist(err):
			app.notFoundResponse(w, r)
		default:
			app.serverErrorResponse(w, r, err)
		}
		return
	}
	defer file.Close()

	i, err := file.Stat()
	if err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=%s", i.Name()))
	http.ServeContent(w, r, i.Name(), time.Time{}, file)
}

func (app *application) deletePicture(w http.ResponseWriter, r *http.Request) {
	picture, ok := r.Context().Value(contextKeyPicture).(*models.Picture)
	if !ok {
		app.serverErrorResponse(w, r, ErrCantRetrieveEntity)
		return
	}

	if err := app.pictures.Delete(r.Context(), picture.ID); err != nil {
		app.serverErrorResponse(w, r, err)
		return
	}

	if err := os.Remove(path.Join(app.config.PicturesPath, picture.Path)); err != nil {
		switch {
		case os.IsNotExist(err):
			app.notFoundResponse(w, r)
		default:
			app.serverErrorResponse(w, r, err)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
