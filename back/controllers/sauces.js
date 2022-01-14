const Sauce = require("../models/Sauce");
const fs = require("fs");

exports.getAllSauces = (req, res, next) => {
    Sauce.find()
        .then(sauces => res.status(200).json(sauces))
        .catch(error => res.status(400).json({ error }));
};

exports.getOneSauce = (req, res, next) => {
    Sauce.findOne({ _id: req.params.id })
        .then(sauce => res.status(200).json(sauce))
        .catch(error => res.status(404).json({ error }));
};

exports.createSauce = (req, res, next) => {
    const sauceObject = JSON.parse(req.body.sauce);
    const sauce = new Sauce({
        ...sauceObject,
        imageUrl: `${req.protocol}://${req.get("host")}/images/${req.file.filename}`,
        likes: 0,
        dislikes: 0,
        userLiked: [],
        userDisliked: []
    });
    sauce.save()
        .then(() => res.status(201).json({ message: "Sauce saved." }))
        .catch(error => res.status(400).json({ error }));
};

exports.modifySauce = (req, res, next) => {
    Sauce.findOne({ _id: req.params.id })
        .then(sauce => {
            if (sauce.userId !== req.auth) {
                res.status(400).json({ error: "Unauthorized request." })
            }
            else if (sauce.userId == req.auth) {
                const filename = sauce.imageUrl.split("/images/")[1];
                fs.unlink(`images/${filename}`, () => {
                    const sauceObject = req.file ?
                        {
                            ...JSON.parse(req.body.sauce),
                            imageUrl: `${req.protocol}://${req.get("host")}/images/${req.file.filename}`
                        } : { ...req.body };
                    Sauce.updateOne({ _id: req.params.id }, { ...sauceObject, _id: req.params.id })
                        .then(() => res.status(200).json({ message: "Sauce modified." }))
                        .catch(error => res.status(400).json({ error }));
                })
            }
        })
        .catch(error => res.status(400).json({ error }));
};

exports.deleteSauce = (req, res, next) => {
    Sauce.findOne({ _id: req.params.id })
        .then(sauce => {
            if (sauce.userId !== req.auth) {
                res.status(400).json({ error: "Unauthorized request." })
            }
            else if (sauce.userId == req.auth) {
                const filename = sauce.imageUrl.split("/images/")[1];
                fs.unlink(`images/${filename}`, () => {
                    Sauce.deleteOne({ _id: req.params.id })
                        .then(() => res.status(200).json({ message: "Sauce deleted." }))
                        .catch(error => res.status(400).json({ error }));
                });
            }
        })
        .catch(error => res.status(500).json({ error }));
};

exports.likeSauce = (req, res, next) => {
    const like = JSON.parse(req.body.like);
    Sauce.findOne({ _id: req.params.id })
        .then(sauce => {
            console.log(sauce);
            let likes = sauce.likes;
            let usersLiked = sauce.usersLiked;
            let dislikes = sauce.dislikes;
            let usersDisliked = sauce.usersDisliked;
            const usersLikedFilter = usersLiked.filter(user => user == req.body.userId);
            const usersDislikedFilter = usersDisliked.filter(user => user == req.body.userId);

            if (like === 1) {
                //if user likes the sauce
                likes++;
                usersLiked.push(req.body.userId);
                let updates = {
                    likes: likes,
                    usersLiked: usersLiked,
                    _id: req.params.id,
                }
                Sauce.updateOne({ _id: req.params.id }, updates)
                    .then(() => res.status(200).json({ message: "Like counted." }))
                    .catch(error => res.status(400).json({ error }));

            } else if (like === -1) {
                //if user dislikes the sauce
                dislikes++;
                usersDisliked.push(req.body.userId);
                let updates = {
                    dislikes: dislikes,
                    usersDisliked: usersDisliked,
                    _id: req.params.id,
                }
                Sauce.updateOne({ _id: req.params.id }, updates)
                    .then(() => res.status(200).json({ message: "Dislike counted." }))
                    .catch(error => res.status(400).json({ error }));

            } else if (like === 0) {
                //if user withdraws his like or dislike
                if (usersLikedFilter != "") {
                    //if user withdraws his like 
                    let positionLike = usersLiked.indexOf(req.body.userId);
                    let newUsersLiked = usersLiked.splice(positionLike, 1);
                    likes--;
                    let updates = {
                        likes: likes,
                        usersLiked: usersLiked,
                        _id: req.params.id,
                    }
                    Sauce.updateOne({ _id: req.params.id }, updates)
                        .then(() => res.status(200).json({ message: "Like discounted." }))
                        .catch(error => res.status(400).json({ error }));

                } else if (usersDislikedFilter != "") {
                    //if user withdraws his dislike
                    let positionDislike = usersDisliked.indexOf(req.body.userId);
                    let newUsersDisliked = usersDisliked.splice(positionDislike, 1);
                    dislikes--;
                    let updates = {
                        dislikes: dislikes,
                        usersDisliked: usersDisliked,
                        _id: req.params.id,
                    }
                    Sauce.updateOne({ _id: req.params.id }, updates)
                        .then(() => res.status(200).json({ message: "Like discounted." }))
                        .catch(error => res.status(400).json({ error }));
                }
            }
        })
        .catch(error => res.status(400).json({ error }));
};